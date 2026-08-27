//! Kubernetes Secrets.
//!
//! The backend where `select` is not really optional. A cluster namespace is
//! full of service-account tokens, TLS material and Helm release state, and
//! almost none of it belongs in a secrets console — so a Store with no
//! selector shows hundreds of objects nobody wanted.
//!
//! It is also the backend `protect` exists for. External Secrets' whole job is
//! syncing secrets *into* a cluster, so without protection keyway would offer
//! to edit exactly the objects a reconcile loop overwrites — and the edit would
//! disappear on the next sync with nothing to show for it.

use crate::domains::secrets::entity::{
    BackendError, Metadata, Secret, SecretManager, Version, VersionState,
};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Secret as K8sSecret;
use kube::api::{Api, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use std::collections::BTreeMap;

/// keyway's own annotation recording which revision a Secret is on.
///
/// Kubernetes has no version history: a Secret has one value, and writing a
/// new one replaces it. keyway reports the resourceVersion as the version id,
/// which is honest — it changes on every write and identifies the current
/// state — but it cannot offer older ones, because they do not exist.
const REVISION: &str = "keyway.io/revision";

pub struct KubernetesSecrets {
    api: Api<K8sSecret>,
    namespace: String,
}

impl KubernetesSecrets {
    /// Connects using the ambient config: a kubeconfig on a laptop, the
    /// service account inside a pod.
    ///
    /// # Errors
    ///
    /// When no cluster configuration can be found.
    pub async fn new(namespace: impl Into<String>) -> eyre::Result<Self> {
        let namespace = namespace.into();
        let client = kube::Client::try_default().await?;
        Ok(Self {
            api: Api::namespaced(client, &namespace),
            namespace,
        })
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// Turns a Kubernetes Secret into keyway's shape.
///
/// The whole `data` map becomes the payload as flat JSON, because a Kubernetes
/// Secret is natively key/value and that is the shape every kv path in keyway
/// expects.
fn into_secret(secret: &K8sSecret) -> Option<Secret> {
    let meta = &secret.metadata;
    Some(Secret {
        store: String::new(),
        name: meta.name.clone()?,
        labels: meta
            .labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        annotations: meta
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        // resourceVersion changes on every write and identifies the current
        // state. It is the only version id a Kubernetes Secret has.
        latest_version: meta.resource_version.clone().unwrap_or_default(),
    })
}

/// The payload, as flat JSON.
///
/// Kubernetes stores values base64-encoded in `data`; the client decodes them
/// into `ByteString`, so what arrives here is already raw.
fn payload_of(secret: &K8sSecret) -> Result<Vec<u8>, BackendError> {
    let mut map = BTreeMap::new();
    for (key, value) in secret.data.clone().unwrap_or_default() {
        map.insert(key, String::from_utf8_lossy(&value.0).into_owned());
    }
    // `stringData` is write-only in the API and normally absent on read, but
    // an object constructed by a controller may carry it.
    for (key, value) in secret.string_data.clone().unwrap_or_default() {
        map.insert(key, value);
    }

    if map.len() == 1
        && let Some(only) = map.get("value")
    {
        return Ok(only.clone().into_bytes());
    }
    serde_json::to_vec(&map).map_err(|e| BackendError::backend("encoding a k8s payload", e))
}

/// The inverse: what to write.
fn bytes_to_string_data(payload: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(payload);
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text) {
        return map
            .into_iter()
            .map(|(key, value)| {
                let rendered = match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                (key, rendered)
            })
            .collect();
    }
    BTreeMap::from([("value".to_owned(), text.into_owned())])
}

fn backend(context: &'static str, error: &kube::Error) -> BackendError {
    if let kube::Error::Api(response) = error
        && response.code == 404
    {
        return BackendError::NotFound;
    }
    BackendError::backend(context, format!("{error}"))
}

#[async_trait]
impl SecretManager for KubernetesSecrets {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        // Unfiltered here on purpose: `select` is applied by the Store, in one
        // place, so a selector cannot be honoured by one backend and forgotten
        // by another.
        let listed = self
            .api
            .list(&ListParams::default())
            .await
            .map_err(|e| backend("listing kubernetes secrets", &e))?;

        Ok(listed.items.iter().filter_map(into_secret).collect())
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        let secret = self
            .api
            .get(name)
            .await
            .map_err(|e| backend("reading a kubernetes secret", &e))?;
        into_secret(&secret).ok_or(BackendError::NotFound)
    }

    /// One version, always.
    ///
    /// Kubernetes keeps no history: a Secret has one value and a write
    /// replaces it. Reporting a single version is the honest answer — inventing
    /// a series would promise older values that cannot be fetched.
    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        let secret = self.get(name).await?;
        Ok(vec![Version {
            id: secret.latest_version,
            state: VersionState::Enabled,
        }])
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        let secret = self
            .api
            .get(name)
            .await
            .map_err(|e| backend("reading a kubernetes secret's value", &e))?;

        // Asking for anything but the current revision is a request Kubernetes
        // cannot serve, and saying so beats quietly returning the current one
        // under a version id the caller did not ask for.
        if let Some(wanted) = version
            && secret.metadata.resource_version.as_deref() != Some(wanted)
        {
            return Err(BackendError::NoSuchVersion(wanted.to_owned()));
        }
        payload_of(&secret)
    }

    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        // A merge patch with the full map replaces it, which is what the trait
        // promises — a strategic merge would only ever add.
        let patch = serde_json::json!({
            "metadata": { "labels": labels }
        });
        self.api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| backend("setting labels on a kubernetes secret", &e))?;
        Ok(())
    }

    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let secret = K8sSecret {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                namespace: Some(self.namespace.clone()),
                labels: Some(labels.into_iter().collect()),
                ..ObjectMeta::default()
            },
            ..K8sSecret::default()
        };
        self.api
            .create(&PostParams::default(), &secret)
            .await
            .map_err(|e| backend("creating a kubernetes secret", &e))?;
        Ok(())
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        let patch = serde_json::json!({
            // `stringData` rather than `data`, so Kubernetes does the base64
            // encoding and keyway cannot get it wrong.
            "stringData": bytes_to_string_data(payload),
            "metadata": { "annotations": { REVISION: "keyway" } }
        });

        let written = self
            .api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| backend("writing a kubernetes secret", &e))?;

        Ok(Version {
            id: written.metadata.resource_version.unwrap_or_default(),
            state: VersionState::Enabled,
        })
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        self.api
            .delete(name, &kube::api::DeleteParams::default())
            .await
            .map_err(|e| backend("deleting a kubernetes secret", &e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;

    fn secret(data: &[(&str, &str)], labels: &[(&str, &str)]) -> K8sSecret {
        K8sSecret {
            metadata: ObjectMeta {
                name: Some("db-creds".to_owned()),
                resource_version: Some("12345".to_owned()),
                labels: Some(
                    labels
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                ),
                ..ObjectMeta::default()
            },
            data: Some(
                data.iter()
                    .map(|(k, v)| ((*k).to_owned(), ByteString(v.as_bytes().to_vec())))
                    .collect(),
            ),
            ..K8sSecret::default()
        }
    }

    #[test]
    fn a_kubernetes_secret_becomes_a_keyway_one() {
        let converted = into_secret(&secret(&[("db_password", "hunter2")], &[("team", "infra")]))
            .expect("converts");

        assert_eq!(converted.name, "db-creds");
        assert_eq!(converted.labels.get("team").unwrap(), "infra");
        // The only version id a Kubernetes Secret has.
        assert_eq!(converted.latest_version, "12345");
    }

    #[test]
    fn a_multi_key_secret_becomes_flat_json() {
        let bytes = payload_of(&secret(
            &[("db_password", "hunter2"), ("api_key", "abc")],
            &[],
        ))
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["db_password"], "hunter2");
        assert_eq!(parsed["api_key"], "abc");
    }

    #[test]
    fn a_lone_value_key_is_a_text_secret() {
        // What this adapter writes for non-JSON input, so it round-trips.
        let bytes = payload_of(&secret(&[("value", "hunter2")], &[])).unwrap();
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn text_and_kv_both_round_trip() {
        for original in [
            &b"hunter2"[..],
            br#"{"db_password":"hunter2","api_key":"abc"}"#,
        ] {
            let back = K8sSecret {
                string_data: Some(bytes_to_string_data(original)),
                ..K8sSecret::default()
            };

            let read = payload_of(&back).unwrap();
            match serde_json::from_slice::<serde_json::Value>(original) {
                Ok(want) => {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&read).unwrap(),
                        want
                    );
                }
                Err(_) => assert_eq!(read, original),
            }
        }
    }

    #[test]
    fn a_secret_with_no_name_is_skipped_rather_than_panicking() {
        // Every object from the API server has one, but the type says it is
        // optional and a panic in a listing would take out the console.
        let nameless = K8sSecret::default();
        assert!(into_secret(&nameless).is_none());
    }

    #[test]
    fn an_empty_secret_reads_as_empty_json() {
        let bytes = payload_of(&K8sSecret::default()).unwrap();
        assert_eq!(bytes, b"{}");
    }

    #[test]
    fn a_reconciler_owned_secret_carries_the_marker_protect_looks_for() {
        // Not this module's rule — `protect` lives in the Store — but the
        // labels have to survive conversion for it to see them.
        let owned = secret(
            &[("db_password", "x")],
            &[("reconcile.external-secrets.io/managed", "true")],
        );
        let converted = into_secret(&owned).unwrap();

        assert_eq!(
            converted
                .labels
                .get("reconcile.external-secrets.io/managed")
                .unwrap(),
            "true"
        );
    }
}
