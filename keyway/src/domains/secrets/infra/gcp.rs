//! Google Secret Manager.
//!
//! Over the REST API rather than a generated client: the surface keyway needs
//! is eight calls, and the mapping between what Google returns and what keyway
//! means is the part worth being able to read.
//!
//! Credentials come from Application Default Credentials, so a laptop works
//! after `gcloud auth application-default login` and a workload identity works
//! with nothing configured.

use crate::domains::secrets::entity::{
    BackendError, Metadata, Secret, SecretManager, Version, VersionState,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;

const BASE: &str = "https://secretmanager.googleapis.com/v1";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

pub struct GcpSecretManager {
    project: String,
    auth: Arc<dyn gcp_auth::TokenProvider>,
    http: reqwest::Client,
}

impl GcpSecretManager {
    /// # Errors
    ///
    /// When no Application Default Credentials can be found.
    pub async fn new(project: impl Into<String>) -> eyre::Result<Self> {
        Ok(Self {
            project: project.into(),
            auth: gcp_auth::provider().await?,
            http: reqwest::Client::new(),
        })
    }

    async fn token(&self) -> Result<String, BackendError> {
        self.auth
            .token(&[SCOPE])
            .await
            .map(|t| t.as_str().to_owned())
            .map_err(|e| BackendError::backend("getting google credentials", e))
    }

    fn parent(&self) -> String {
        format!("projects/{}", self.project)
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

        // 404 is an answer, not a failure: it is what "no such secret" looks
        // like, and the caller reports it identically to a secret outside
        // `select`.
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(BackendError::NotFound);
        }
        let response = response
            .error_for_status()
            .map_err(|e| BackendError::backend(context, e))?;
        response
            .json()
            .await
            .map_err(|e| BackendError::backend(context, e))
    }
}

/// What Google calls a secret.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSecret {
    /// `projects/p/secrets/name`.
    name: String,
    #[serde(default)]
    labels: Metadata,
    #[serde(default)]
    annotations: Metadata,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSecrets {
    #[serde(default)]
    secrets: Vec<GcpSecret>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpVersion {
    /// `projects/p/secrets/s/versions/7`.
    name: String,
    #[serde(default)]
    state: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListVersions {
    #[serde(default)]
    versions: Vec<GcpVersion>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessResponse {
    payload: Payload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    #[serde(default)]
    data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddVersionResponse {
    name: String,
}

/// The last segment of a Google resource name.
///
/// `projects/p/secrets/db-creds` is a full path; keyway addresses by the leaf,
/// and every other backend reports one.
fn leaf(resource: &str) -> &str {
    resource.rsplit('/').next().unwrap_or(resource)
}

/// Google's version states, as keyway means them.
fn state_of(word: &str) -> VersionState {
    match word {
        "ENABLED" => VersionState::Enabled,
        "DISABLED" => VersionState::Disabled,
        // DESTROYED, and anything a future API adds. A state this build does
        // not understand must not be offered for reveal.
        _ => VersionState::Destroyed,
    }
}

#[async_trait]
impl SecretManager for GcpSecretManager {
    /// Pages through the project rather than fanning out a request per secret:
    /// this is the first screen of the console.
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;

        loop {
            let mut request = self
                .http
                .get(format!("{BASE}/{}/secrets", self.parent()))
                .query(&[("pageSize", "1000")]);
            if let Some(token) = &page {
                request = request.query(&[("pageToken", token.as_str())]);
            }

            let listed: ListSecrets = self.send(request, "listing google secrets").await?;
            out.extend(listed.secrets.into_iter().map(|s| Secret {
                store: String::new(),
                name: leaf(&s.name).to_owned(),
                labels: s.labels,
                annotations: s.annotations,
                // Deliberately absent: resolving it costs one call per secret,
                // and a list that makes N requests is a list nobody waits for.
                latest_version: String::new(),
            }));

            page = listed.next_page_token.filter(|t| !t.is_empty());
            if page.is_none() {
                return Ok(out);
            }
        }
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        let encoded = urlencoding::encode(name);
        let secret: GcpSecret = self
            .send(
                self.http
                    .get(format!("{BASE}/{}/secrets/{encoded}", self.parent())),
                "reading a google secret",
            )
            .await?;

        // One extra call, and only here: a caller who opened one secret is
        // waiting for one secret.
        let latest = self
            .versions(name)
            .await?
            .into_iter()
            .find(|v| v.state == VersionState::Enabled)
            .map(|v| v.id)
            .unwrap_or_default();

        Ok(Secret {
            store: String::new(),
            name: leaf(&secret.name).to_owned(),
            labels: secret.labels,
            annotations: secret.annotations,
            latest_version: latest,
        })
    }

    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        let encoded = urlencoding::encode(name);
        let mut out = Vec::new();
        let mut page: Option<String> = None;

        loop {
            let mut request = self
                .http
                .get(format!(
                    "{BASE}/{}/secrets/{encoded}/versions",
                    self.parent()
                ))
                .query(&[("pageSize", "1000")]);
            if let Some(token) = &page {
                request = request.query(&[("pageToken", token.as_str())]);
            }

            let listed: ListVersions = self.send(request, "listing google versions").await?;
            out.extend(listed.versions.into_iter().map(|v| Version {
                id: leaf(&v.name).to_owned(),
                state: state_of(&v.state),
            }));

            page = listed.next_page_token.filter(|t| !t.is_empty());
            if page.is_none() {
                // Google returns newest first; keyway promises the same.
                return Ok(out);
            }
        }
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        use base64::Engine as _;

        let encoded = urlencoding::encode(name);
        let version = version.unwrap_or("latest");
        let accessed: AccessResponse = self
            .send(
                self.http.get(format!(
                    "{BASE}/{}/secrets/{encoded}/versions/{version}:access",
                    self.parent()
                )),
                "reading a google secret's value",
            )
            .await?;

        // Google returns the payload base64-encoded, in the standard alphabet.
        base64::engine::general_purpose::STANDARD
            .decode(accessed.payload.data.trim())
            .map_err(|e| BackendError::backend("decoding a google payload", e))
    }

    /// Replaces the labels, which is what Google's PATCH does with an
    /// `updateMask` of `labels` — and what the trait promises.
    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let encoded = urlencoding::encode(name);
        let _: serde_json::Value = self
            .send(
                self.http
                    .patch(format!("{BASE}/{}/secrets/{encoded}", self.parent()))
                    .query(&[("updateMask", "labels")])
                    .json(&serde_json::json!({ "labels": labels })),
                "setting labels on a google secret",
            )
            .await?;
        Ok(())
    }

    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let _: serde_json::Value = self
            .send(
                self.http
                    .post(format!("{BASE}/{}/secrets", self.parent()))
                    .query(&[("secretId", name)])
                    .json(&serde_json::json!({
                        "labels": labels,
                        // Google requires a replication policy and has no
                        // default. Automatic is the one a deployment that has
                        // not said otherwise means.
                        "replication": { "automatic": {} }
                    })),
                "creating a google secret",
            )
            .await?;
        Ok(())
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        use base64::Engine as _;

        let encoded = urlencoding::encode(name);
        let added: AddVersionResponse = self
            .send(
                self.http
                    .post(format!(
                        "{BASE}/{}/secrets/{encoded}:addVersion",
                        self.parent()
                    ))
                    .json(&serde_json::json!({
                        "payload": {
                            "data": base64::engine::general_purpose::STANDARD.encode(payload)
                        }
                    })),
                "adding a google secret version",
            )
            .await?;

        Ok(Version {
            id: leaf(&added.name).to_owned(),
            state: VersionState::Enabled,
        })
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        let encoded = urlencoding::encode(name);
        let _: serde_json::Value = self
            .send(
                self.http
                    .delete(format!("{BASE}/{}/secrets/{encoded}", self.parent())),
                "deleting a google secret",
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resource_name_reduces_to_its_leaf() {
        // keyway addresses by the leaf; every other backend reports one.
        assert_eq!(leaf("projects/acme/secrets/db-creds"), "db-creds");
        assert_eq!(leaf("projects/acme/secrets/db-creds/versions/7"), "7");
        assert_eq!(leaf("db-creds"), "db-creds");
    }

    #[test]
    fn google_states_map_onto_keyway_states() {
        assert_eq!(state_of("ENABLED"), VersionState::Enabled);
        assert_eq!(state_of("DISABLED"), VersionState::Disabled);
        assert_eq!(state_of("DESTROYED"), VersionState::Destroyed);
    }

    #[test]
    fn a_state_this_build_does_not_know_is_not_revealable() {
        // Google may add one. Reading it as enabled would offer to reveal a
        // payload that may not be there.
        assert_eq!(state_of("SOMETHING_NEW"), VersionState::Destroyed);
        assert_eq!(state_of(""), VersionState::Destroyed);
    }

    #[test]
    fn a_listing_is_parsed_with_its_page_token() {
        let body = serde_json::json!({
            "secrets": [
                { "name": "projects/acme/secrets/db-creds", "labels": { "team": "infra" } },
                { "name": "projects/acme/secrets/api-key" }
            ],
            "nextPageToken": "abc"
        });
        let listed: ListSecrets = serde_json::from_value(body).unwrap();

        assert_eq!(listed.secrets.len(), 2);
        assert_eq!(leaf(&listed.secrets[0].name), "db-creds");
        assert_eq!(listed.secrets[0].labels.get("team").unwrap(), "infra");
        assert!(listed.secrets[1].labels.is_empty());
        assert_eq!(listed.next_page_token.as_deref(), Some("abc"));
    }

    #[test]
    fn a_final_page_has_no_token() {
        let listed: ListSecrets =
            serde_json::from_value(serde_json::json!({ "secrets": [] })).unwrap();
        assert!(listed.next_page_token.is_none());
    }

    #[test]
    fn a_payload_is_base64_in_the_standard_alphabet() {
        use base64::Engine as _;
        let accessed: AccessResponse = serde_json::from_value(serde_json::json!({
            "payload": { "data": "aHVudGVyMg==" }
        }))
        .unwrap();

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(accessed.payload.data.trim())
            .unwrap();
        assert_eq!(decoded, b"hunter2");
    }
}
