//! AWS Secrets Manager.
//!
//! Two things differ from the other backends, and both are mapped here:
//!
//! 1. **AWS spells labels `tags`**, which is why the generic `select` carries
//!    a `tags` map — this is the backend that reads it.
//! 2. **Versions are staged, not numbered.** AWS identifies a version by an
//!    opaque `VersionId` and marks the current one with the `AWSCURRENT` stage
//!    label, so "latest" is a stage rather than a maximum.
//!
//! Credentials come from the standard provider chain, so an instance role or
//! IRSA works with nothing configured.

use crate::domains::secrets::entity::{
    BackendError, Metadata, Secret, SecretManager, Version, VersionState,
};
use async_trait::async_trait;
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::types::Tag;

/// The stage AWS marks the version an unqualified read resolves to.
const CURRENT: &str = "AWSCURRENT";

/// The stage the previous version keeps after a rotation.
const PREVIOUS: &str = "AWSPREVIOUS";

pub struct AwsSecretsManager {
    client: Client,
}

impl AwsSecretsManager {
    /// Builds a client from the standard provider chain.
    pub async fn new(region: Option<String>) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_config::Region::new(region));
        }
        Self {
            client: Client::new(&loader.load().await),
        }
    }
}

/// AWS reports tags as a list of pairs; keyway means a map.
fn tags_to_metadata(tags: Option<&[Tag]>) -> Metadata {
    tags.unwrap_or_default()
        .iter()
        .filter_map(|tag| Some((tag.key()?.to_owned(), tag.value()?.to_owned())))
        .collect()
}

fn metadata_to_tags(labels: &Metadata) -> Vec<Tag> {
    labels
        .iter()
        .filter_map(|(key, value)| Tag::builder().key(key).value(value).build().into())
        .collect()
}

/// What a version's stage labels mean.
///
/// AWS has no per-version enabled/disabled flag: a version either carries a
/// stage or it does not, and one carrying none is pending deletion and cannot
/// be read. So `AWSCURRENT` and `AWSPREVIOUS` are readable and everything else
/// is not — which is the honest mapping, since offering to reveal a stageless
/// version would fail at the call.
fn state_of(stages: Option<&[String]>) -> VersionState {
    let stages = stages.unwrap_or_default();
    if stages.iter().any(|s| s == CURRENT) {
        VersionState::Enabled
    } else if stages.iter().any(|s| s == PREVIOUS) {
        VersionState::Disabled
    } else {
        VersionState::Destroyed
    }
}

/// AWS carries a value as either a string or bytes. keyway's trait carries
/// bytes, and a string is the common case.
fn payload_of(
    string: Option<&str>,
    binary: Option<&aws_sdk_secretsmanager::primitives::Blob>,
) -> Vec<u8> {
    string.map_or_else(
        || binary.map(|b| b.as_ref().to_vec()).unwrap_or_default(),
        |s| s.as_bytes().to_vec(),
    )
}

/// Whether an AWS failure means "no such secret".
fn is_not_found<E: std::fmt::Debug>(error: &E) -> bool {
    // The SDK's error enums differ per operation, so this reads the rendered
    // form rather than matching six near-identical variants.
    format!("{error:?}").contains("ResourceNotFound")
}

fn backend<E: std::fmt::Debug>(context: &'static str, error: &E) -> BackendError {
    if is_not_found(error) {
        return BackendError::NotFound;
    }
    BackendError::backend(context, format!("{error:?}"))
}

#[async_trait]
impl SecretManager for AwsSecretsManager {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        let mut out = Vec::new();
        let mut pages = self
            .client
            .list_secrets()
            .max_results(100)
            .into_paginator()
            .send();

        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| backend("listing aws secrets", &e))?;
            for entry in page.secret_list() {
                let Some(name) = entry.name() else { continue };
                out.push(Secret {
                    store: String::new(),
                    name: name.to_owned(),
                    labels: tags_to_metadata(Some(entry.tags())),
                    annotations: Metadata::new(),
                    // AWS does not report a version id in a listing, and
                    // resolving one costs a call per secret.
                    latest_version: String::new(),
                });
            }
        }
        Ok(out)
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        let described = self
            .client
            .describe_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| backend("reading an aws secret", &e))?;

        // The stage map is version id → stages, so the current one is found by
        // looking for the label rather than by ordering.
        let current = described
            .version_ids_to_stages()
            .and_then(|stages| {
                stages
                    .iter()
                    .find(|(_, labels)| labels.iter().any(|l| l == CURRENT))
                    .map(|(id, _)| id.clone())
            })
            .unwrap_or_default();

        Ok(Secret {
            store: String::new(),
            name: described.name().unwrap_or(name).to_owned(),
            labels: tags_to_metadata(Some(described.tags())),
            annotations: Metadata::new(),
            latest_version: current,
        })
    }

    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        let listed = self
            .client
            .list_secret_version_ids()
            .secret_id(name)
            .include_deprecated(true)
            .send()
            .await
            .map_err(|e| backend("listing aws versions", &e))?;

        let mut versions: Vec<(i64, Version)> = listed
            .versions()
            .iter()
            .filter_map(|v| {
                let id = v.version_id()?.to_owned();
                Some((
                    v.created_date()
                        .map_or(i64::MIN, aws_sdk_secretsmanager::primitives::DateTime::secs),
                    Version {
                        id,
                        state: state_of(Some(v.version_stages())),
                    },
                ))
            })
            .collect();

        // Newest first, which is what the trait promises and what AWS does not
        // guarantee.
        versions.sort_by_key(|(created, _)| std::cmp::Reverse(*created));
        Ok(versions.into_iter().map(|(_, v)| v).collect())
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        let mut request = self.client.get_secret_value().secret_id(name);
        match version {
            Some(id) => request = request.version_id(id),
            // Explicit rather than implied: the default is AWSCURRENT anyway,
            // but saying so is what makes the mapping legible.
            None => request = request.version_stage(CURRENT),
        }

        let value = request
            .send()
            .await
            .map_err(|e| backend("reading an aws secret's value", &e))?;
        Ok(payload_of(value.secret_string(), value.secret_binary()))
    }

    /// Replaces the tags, which is what the trait promises — so tags AWS holds
    /// and the caller did not send are removed.
    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let existing = self
            .client
            .describe_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| backend("reading an aws secret's tags", &e))?;

        let stale: Vec<String> = tags_to_metadata(Some(existing.tags()))
            .into_keys()
            .filter(|key| !labels.contains_key(key))
            .collect();
        if !stale.is_empty() {
            self.client
                .untag_resource()
                .secret_id(name)
                .set_tag_keys(Some(stale))
                .send()
                .await
                .map_err(|e| backend("removing aws tags", &e))?;
        }

        if !labels.is_empty() {
            self.client
                .tag_resource()
                .secret_id(name)
                .set_tags(Some(metadata_to_tags(&labels)))
                .send()
                .await
                .map_err(|e| backend("setting aws tags", &e))?;
        }
        Ok(())
    }

    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        self.client
            .create_secret()
            .name(name)
            .set_tags(Some(metadata_to_tags(&labels)))
            .send()
            .await
            .map_err(|e| backend("creating an aws secret", &e))?;
        Ok(())
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        let written = self
            .client
            .put_secret_value()
            .secret_id(name)
            .secret_string(String::from_utf8_lossy(payload))
            .send()
            .await
            .map_err(|e| backend("adding an aws secret version", &e))?;

        Ok(Version {
            id: written.version_id().unwrap_or_default().to_owned(),
            state: VersionState::Enabled,
        })
    }

    /// Destroys immediately rather than scheduling.
    ///
    /// AWS defaults to a recovery window, which sounds safer and is not what a
    /// caller of `delete` asked for: a scheduled secret still occupies its
    /// name, so recreating it fails and the console shows a deletion that did
    /// not happen.
    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        self.client
            .delete_secret()
            .secret_id(name)
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|e| backend("deleting an aws secret", &e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(key: &str, value: &str) -> Tag {
        Tag::builder().key(key).value(value).build()
    }

    #[test]
    fn aws_tags_become_keyway_labels() {
        // The reason `select` carries a `tags` map: this is the backend that
        // spells labels differently.
        let tags = [tag("team", "infra"), tag("keyway", "true")];
        let labels = tags_to_metadata(Some(&tags));

        assert_eq!(labels.get("team").unwrap(), "infra");
        assert_eq!(labels.get("keyway").unwrap(), "true");
    }

    #[test]
    fn labels_round_trip_through_tags() {
        let mut labels = Metadata::new();
        labels.insert("team".to_owned(), "infra".to_owned());

        let back = tags_to_metadata(Some(&metadata_to_tags(&labels)));
        assert_eq!(back, labels);
    }

    #[test]
    fn no_tags_is_no_labels() {
        assert!(tags_to_metadata(None).is_empty());
        assert!(tags_to_metadata(Some(&[])).is_empty());
    }

    #[test]
    fn the_current_stage_is_the_readable_one() {
        assert_eq!(state_of(Some(&[CURRENT.to_owned()])), VersionState::Enabled);
        assert_eq!(
            state_of(Some(&[PREVIOUS.to_owned()])),
            VersionState::Disabled
        );
    }

    #[test]
    fn a_version_carrying_no_stage_cannot_be_read() {
        // AWS has no enabled/disabled flag: a stageless version is pending
        // deletion, and offering to reveal it would fail at the call.
        assert_eq!(state_of(Some(&[])), VersionState::Destroyed);
        assert_eq!(state_of(None), VersionState::Destroyed);
    }

    #[test]
    fn a_custom_stage_alone_is_not_readable() {
        // Somebody's own label is not AWSCURRENT.
        assert_eq!(
            state_of(Some(&["MY_STAGE".to_owned()])),
            VersionState::Destroyed
        );
    }

    #[test]
    fn a_string_value_is_preferred_over_bytes() {
        let blob = aws_sdk_secretsmanager::primitives::Blob::new(b"binary".to_vec());
        assert_eq!(payload_of(Some("hunter2"), Some(&blob)), b"hunter2");
    }

    #[test]
    fn a_binary_value_is_carried_through() {
        let blob = aws_sdk_secretsmanager::primitives::Blob::new(b"\x00\x01\x02".to_vec());
        assert_eq!(payload_of(None, Some(&blob)), b"\x00\x01\x02");
    }

    #[test]
    fn a_secret_with_neither_reads_as_empty() {
        assert!(payload_of(None, None).is_empty());
    }

    #[test]
    fn a_missing_resource_is_recognised_however_it_is_worded() {
        assert!(is_not_found(&"ResourceNotFoundException: no such secret"));
        assert!(!is_not_found(&"AccessDeniedException"));
    }
}
