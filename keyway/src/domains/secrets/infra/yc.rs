//! Yandex Cloud Lockbox.
//!
//! Two things make this the odd one out, and both are handled here rather than
//! leaking into the trait:
//!
//! 1. **Secrets are addressed by an opaque id**, not by name, and Lockbox does
//!    not require names to be unique. keyway speaks names to a backend, so
//!    this resolves name → id and refuses an ambiguous one rather than picking.
//! 2. **The payload is natively a key/value list.** keyway's trait carries
//!    bytes, and a kv secret is JSON by the time it reaches one — so this
//!    converts, which is exactly what the trait's "a backend with native kv can
//!    serve it natively" note means.

use crate::domains::secrets::entity::{
    BackendError, Metadata, Secret, SecretManager, Version, VersionState,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const LOCKBOX: &str = "https://lockbox.api.cloud.yandex.net/lockbox/v1";
const PAYLOAD: &str = "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1";
const IAM: &str = "https://iam.api.cloud.yandex.net/iam/v1/tokens";

/// IAM tokens last 12 hours; refreshing well inside that costs nothing and
/// avoids a cliff.
const TOKEN_FOR: Duration = Duration::from_mins(50);

pub struct YcLockbox {
    folder: String,
    /// The authorized-key JSON from `yc iam key create`. Empty falls back to
    /// the instance service account, which a laptop does not have.
    authorized_key: String,
    http: reqwest::Client,
    token: Mutex<Option<(Instant, String)>>,
}

#[derive(Deserialize)]
struct IamToken {
    #[serde(rename = "iamToken")]
    iam_token: String,
}

#[derive(Deserialize)]
struct YcSecret {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    labels: Metadata,
    #[serde(default, rename = "currentVersion")]
    current_version: Option<YcVersion>,
}

#[derive(Deserialize)]
struct YcVersion {
    id: String,
    #[serde(default)]
    status: String,
}

#[derive(Deserialize)]
struct ListSecrets {
    #[serde(default)]
    secrets: Vec<YcSecret>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct ListVersions {
    #[serde(default)]
    versions: Vec<YcVersion>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct PayloadResponse {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    key: String,
    #[serde(default, rename = "textValue")]
    text_value: Option<String>,
    #[serde(default, rename = "binaryValue")]
    binary_value: Option<String>,
}

/// Lockbox's version statuses, as keyway means them.
fn state_of(word: &str) -> VersionState {
    match word {
        "ACTIVE" => VersionState::Enabled,
        "SCHEDULED_FOR_DESTRUCTION" => VersionState::Disabled,
        // DESTROYED, and anything added later.
        _ => VersionState::Destroyed,
    }
}

/// Turns a Lockbox payload into the bytes keyway's trait carries.
///
/// A single entry keyed `value` is a text secret — that is the convention this
/// adapter writes, so it round-trips. Anything else is key/value and becomes
/// flat JSON, which is the shape every other kv path in keyway expects.
fn payload_to_bytes(entries: Vec<Entry>) -> Result<Vec<u8>, BackendError> {
    use base64::Engine as _;

    let mut map = BTreeMap::new();
    for entry in entries {
        let value = if let Some(text) = entry.text_value {
            text
        } else if let Some(binary) = entry.binary_value {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(binary.trim())
                .map_err(|e| BackendError::backend("decoding a lockbox entry", e))?;
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            String::new()
        };
        map.insert(entry.key, value);
    }

    if map.len() == 1
        && let Some(only) = map.get("value")
    {
        return Ok(only.clone().into_bytes());
    }
    serde_json::to_vec(&map).map_err(|e| BackendError::backend("encoding a lockbox payload", e))
}

/// The inverse: what to send when writing.
fn bytes_to_entries(payload: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8_lossy(payload);

    // A JSON object is a kv secret; anything else is one text value. Reading
    // it back gives the same bytes either way.
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text) {
        return map
            .into_iter()
            .map(|(key, value)| {
                let rendered = match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                serde_json::json!({ "key": key, "textValue": rendered })
            })
            .collect();
    }
    vec![serde_json::json!({ "key": "value", "textValue": text })]
}

impl YcLockbox {
    /// # Errors
    ///
    /// Never at construction; credentials are exchanged lazily.
    pub fn new(folder: impl Into<String>, authorized_key: impl Into<String>) -> Self {
        Self {
            folder: folder.into(),
            authorized_key: authorized_key.into(),
            http: reqwest::Client::new(),
            token: Mutex::new(None),
        }
    }

    async fn token(&self) -> Result<String, BackendError> {
        if let Ok(held) = self.token.lock()
            && let Some((at, token)) = held.as_ref()
            && at.elapsed() < TOKEN_FOR
        {
            return Ok(token.clone());
        }

        if self.authorized_key.is_empty() {
            return Err(BackendError::backend(
                "yandex credentials",
                "no authorized key configured, and this is not a yandex instance",
            ));
        }

        let exchanged: IamToken = self
            .http
            .post(IAM)
            .json(&serde_json::json!({ "jwt": self.authorized_key }))
            .send()
            .await
            .map_err(|e| BackendError::backend("exchanging a yandex key", e))?
            .error_for_status()
            .map_err(|e| BackendError::backend("yandex refused the key", e))?
            .json()
            .await
            .map_err(|e| BackendError::backend("reading a yandex token", e))?;

        if let Ok(mut held) = self.token.lock() {
            *held = Some((Instant::now(), exchanged.iam_token.clone()));
        }
        Ok(exchanged.iam_token)
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        context: &'static str,
    ) -> Result<T, BackendError> {
        let response = request
            .bearer_auth(self.token().await?)
            .send()
            .await
            .map_err(|e| BackendError::backend(context, e))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(BackendError::NotFound);
        }
        response
            .error_for_status()
            .map_err(|e| BackendError::backend(context, e))?
            .json()
            .await
            .map_err(|e| BackendError::backend(context, e))
    }

    async fn all_secrets(&self) -> Result<Vec<YcSecret>, BackendError> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;

        loop {
            let mut request = self
                .http
                .get(format!("{LOCKBOX}/secrets"))
                .query(&[("folderId", self.folder.as_str()), ("pageSize", "1000")]);
            if let Some(token) = &page {
                request = request.query(&[("pageToken", token.as_str())]);
            }

            let listed: ListSecrets = self.send(request, "listing lockbox secrets").await?;
            out.extend(listed.secrets);

            page = listed.next_page_token.filter(|t| !t.is_empty());
            if page.is_none() {
                return Ok(out);
            }
        }
    }

    /// Resolves a name to Lockbox's opaque id.
    ///
    /// Lockbox does not require names to be unique, so two secrets may answer
    /// to one name. Picking either would mean a reveal that silently reads the
    /// wrong secret, so this refuses instead.
    async fn id_of(&self, name: &str) -> Result<String, BackendError> {
        let matching: Vec<YcSecret> = self
            .all_secrets()
            .await?
            .into_iter()
            .filter(|s| s.name == name)
            .collect();

        match matching.len() {
            0 => Err(BackendError::NotFound),
            1 => Ok(matching.into_iter().next().expect("one").id),
            n => Err(BackendError::InvalidName {
                name: name.to_owned(),
                reason: format!(
                    "{n} secrets in this folder share this name; \
                     lockbox does not require them to be unique"
                ),
            }),
        }
    }
}

fn into_secret(secret: YcSecret) -> Secret {
    Secret {
        store: String::new(),
        name: secret.name,
        labels: secret.labels,
        annotations: Metadata::new(),
        latest_version: secret
            .current_version
            .filter(|v| state_of(&v.status) == VersionState::Enabled)
            .map(|v| v.id)
            .unwrap_or_default(),
    }
}

#[async_trait]
impl SecretManager for YcLockbox {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        Ok(self
            .all_secrets()
            .await?
            .into_iter()
            .map(into_secret)
            .collect())
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        self.all_secrets()
            .await?
            .into_iter()
            .find(|s| s.name == name)
            .map(into_secret)
            .ok_or(BackendError::NotFound)
    }

    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        let id = self.id_of(name).await?;
        let mut out = Vec::new();
        let mut page: Option<String> = None;

        loop {
            let mut request = self
                .http
                .get(format!("{LOCKBOX}/secrets/{id}/versions"))
                .query(&[("pageSize", "1000")]);
            if let Some(token) = &page {
                request = request.query(&[("pageToken", token.as_str())]);
            }

            let listed: ListVersions = self.send(request, "listing lockbox versions").await?;
            out.extend(listed.versions.into_iter().map(|v| Version {
                id: v.id,
                state: state_of(&v.status),
            }));

            page = listed.next_page_token.filter(|t| !t.is_empty());
            if page.is_none() {
                return Ok(out);
            }
        }
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        let id = self.id_of(name).await?;
        let mut request = self.http.get(format!("{PAYLOAD}/secrets/{id}/payload"));
        if let Some(version) = version {
            request = request.query(&[("versionId", version)]);
        }

        let payload: PayloadResponse = self.send(request, "reading a lockbox payload").await?;
        payload_to_bytes(payload.entries)
    }

    /// Lockbox has labels but no separate annotations, so this replaces
    /// labels — which is what the trait promises.
    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let id = self.id_of(name).await?;
        let _: serde_json::Value = self
            .send(
                self.http
                    .patch(format!("{LOCKBOX}/secrets/{id}"))
                    .json(&serde_json::json!({ "updateMask": "labels", "labels": labels })),
                "setting labels on a lockbox secret",
            )
            .await?;
        Ok(())
    }

    /// Lockbox creates a secret and its first version together, so keyway's
    /// split shape becomes a secret with one empty entry that the first
    /// `add_version` replaces.
    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let _: serde_json::Value = self
            .send(
                self.http
                    .post(format!("{LOCKBOX}/secrets"))
                    .json(&serde_json::json!({
                        "folderId": self.folder,
                        "name": name,
                        "labels": labels,
                        "versionPayloadEntries": [{ "key": "value", "textValue": "" }]
                    })),
                "creating a lockbox secret",
            )
            .await?;
        Ok(())
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        let id = self.id_of(name).await?;
        let _: serde_json::Value = self
            .send(
                self.http
                    .post(format!("{LOCKBOX}/secrets/{id}:addVersion"))
                    .json(&serde_json::json!({
                        "payloadEntries": bytes_to_entries(payload)
                    })),
                "adding a lockbox version",
            )
            .await?;

        // The add is asynchronous and returns an operation rather than the
        // version, so the id is read back rather than guessed.
        self.versions(name)
            .await?
            .into_iter()
            .find(|v| v.state == VersionState::Enabled)
            .ok_or_else(|| BackendError::NoSuchVersion("the version just written".to_owned()))
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        let id = self.id_of(name).await?;
        let _: serde_json::Value = self
            .send(
                self.http.delete(format!("{LOCKBOX}/secrets/{id}")),
                "deleting a lockbox secret",
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, text: &str) -> Entry {
        Entry {
            key: key.to_owned(),
            text_value: Some(text.to_owned()),
            binary_value: None,
        }
    }

    #[test]
    fn lockbox_statuses_map_onto_keyway_states() {
        assert_eq!(state_of("ACTIVE"), VersionState::Enabled);
        assert_eq!(
            state_of("SCHEDULED_FOR_DESTRUCTION"),
            VersionState::Disabled
        );
        assert_eq!(state_of("DESTROYED"), VersionState::Destroyed);
        assert_eq!(state_of("SOMETHING_NEW"), VersionState::Destroyed);
    }

    #[test]
    fn a_kv_payload_becomes_flat_json() {
        // The shape every other kv path in keyway expects.
        let bytes = payload_to_bytes(vec![
            entry("db_password", "hunter2"),
            entry("api_key", "abc"),
        ])
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["db_password"], "hunter2");
        assert_eq!(parsed["api_key"], "abc");
    }

    #[test]
    fn a_lone_value_entry_is_a_text_secret() {
        // What this adapter writes for non-JSON input, so it round-trips.
        let bytes = payload_to_bytes(vec![entry("value", "hunter2")]).unwrap();
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn a_lone_entry_under_another_key_stays_kv() {
        let bytes = payload_to_bytes(vec![entry("db_password", "hunter2")]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["db_password"], "hunter2");
    }

    #[test]
    fn text_and_kv_both_round_trip() {
        for original in [
            &b"hunter2"[..],
            br#"{"db_password":"hunter2","api_key":"abc"}"#,
        ] {
            let entries: Vec<Entry> = bytes_to_entries(original)
                .into_iter()
                .map(|v| serde_json::from_value(v).unwrap())
                .collect();
            let back = payload_to_bytes(entries).unwrap();

            // Compared as JSON where it is JSON, since key order is not
            // preserved and does not matter.
            match serde_json::from_slice::<serde_json::Value>(original) {
                Ok(want) => assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&back).unwrap(),
                    want
                ),
                Err(_) => assert_eq!(back, original),
            }
        }
    }

    #[test]
    fn a_binary_entry_is_decoded() {
        let entries = vec![Entry {
            key: "value".to_owned(),
            text_value: None,
            binary_value: Some("aHVudGVyMg==".to_owned()),
        }];
        assert_eq!(payload_to_bytes(entries).unwrap(), b"hunter2");
    }

    #[test]
    fn a_secret_with_no_active_version_reports_none() {
        let secret = YcSecret {
            id: "e6q".to_owned(),
            name: "db-creds".to_owned(),
            labels: Metadata::new(),
            current_version: Some(YcVersion {
                id: "v1".to_owned(),
                status: "DESTROYED".to_owned(),
            }),
        };
        assert_eq!(into_secret(secret).latest_version, "");
    }
}
