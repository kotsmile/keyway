//! One configured backing service, and the fence around it.

use super::{BackendError, Metadata, Secret, SecretManager, Version};
use crate::config::{Selector, StoreConfig, Verb};

/// One configured backing service: a [`SecretManager`] with the scope, the
/// verbs and the protections its declaration gave it.
///
/// Every call goes through here rather than to the adapter directly. `allow`
/// is a fence rather than a hint, and putting it in one place means a new
/// adapter cannot forget to check it — the worst kind of bug to ship in a
/// secrets tool, because nothing about it looks wrong until somebody deletes
/// a production secret from a Store that was meant to be read-only.
pub struct Store {
    config: StoreConfig,
    manager: Box<dyn SecretManager>,
}

/// What a Store refuses, on top of what a backend can fail with.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// This deployment did not grant that verb here.
    #[error("{store} does not allow {verb:?}")]
    NotAllowed { store: String, verb: Verb },
    /// A reconciler owns this secret. Reported with the marker that says so,
    /// because "you may not edit this" without naming the owner leaves the
    /// reader with nowhere to go.
    #[error("{name} is managed by {marker}; edit the source instead")]
    Protected { name: String, marker: String },
    #[error(transparent)]
    Backend(#[from] BackendError),
}

impl Store {
    /// Mounts a configured Store over its adapter.
    #[must_use]
    pub fn new(config: StoreConfig, manager: Box<dyn SecretManager>) -> Self {
        Self { config, manager }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.config.id
    }

    #[must_use]
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Every secret this Store exposes: what the backend holds, narrowed by
    /// `select`.
    ///
    /// # Errors
    ///
    /// When `read` is not allowed, or the backend fails.
    pub async fn list(&self) -> Result<Vec<Secret>, StoreError> {
        self.require(Verb::Read)?;
        let mut secrets = self.manager.list().await?;
        secrets.retain(|secret| self.selects(secret));
        for secret in &mut secrets {
            secret.store.clone_from(&self.config.id);
        }
        Ok(secrets)
    }

    /// One secret's metadata.
    ///
    /// A secret outside `select` reports [`BackendError::NotFound`] rather
    /// than a refusal: a Store that does not expose something should not
    /// confirm it exists.
    ///
    /// # Errors
    ///
    /// When `read` is not allowed, the secret is not exposed, or the backend
    /// fails.
    pub async fn get(&self, name: &str) -> Result<Secret, StoreError> {
        self.require(Verb::Read)?;
        let mut secret = self.manager.get(name).await?;
        if !self.selects(&secret) {
            return Err(BackendError::NotFound.into());
        }
        secret.store.clone_from(&self.config.id);
        Ok(secret)
    }

    /// The revision series, newest first.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn versions(&self, name: &str) -> Result<Vec<Version>, StoreError> {
        self.get(name).await?;
        Ok(self.manager.versions(name).await?)
    }

    /// One version's payload. `None` means the latest.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, StoreError> {
        self.get(name).await?;
        Ok(self.manager.access(name, version).await?)
    }

    /// Writes a new revision.
    ///
    /// # Errors
    ///
    /// When `edit` is not allowed, a reconciler owns the secret, or the
    /// backend fails.
    pub async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, StoreError> {
        self.require(Verb::Edit)?;
        let secret = self.get(name).await?;
        self.require_unprotected(&secret)?;
        Ok(self.manager.add_version(name, payload).await?)
    }

    /// Replaces a secret's labels.
    ///
    /// # Errors
    ///
    /// As [`Self::add_version`].
    pub async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), StoreError> {
        self.require(Verb::Edit)?;
        let secret = self.get(name).await?;
        self.require_unprotected(&secret)?;
        Ok(self.manager.set_labels(name, labels).await?)
    }

    /// Brings a new secret into existence.
    ///
    /// # Errors
    ///
    /// When `create` is not allowed, or the backend fails.
    pub async fn create(&self, name: &str, labels: Metadata) -> Result<(), StoreError> {
        self.require(Verb::Create)?;
        Ok(self.manager.create(name, labels).await?)
    }

    /// Destroys a secret and every version of it.
    ///
    /// # Errors
    ///
    /// When `delete` is not allowed, a reconciler owns the secret, or the
    /// backend fails.
    pub async fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.require(Verb::Delete)?;
        let secret = self.get(name).await?;
        self.require_unprotected(&secret)?;
        Ok(self.manager.delete(name).await?)
    }

    fn require(&self, verb: Verb) -> Result<(), StoreError> {
        if self.config.can(verb) {
            Ok(())
        } else {
            Err(StoreError::NotAllowed {
                store: self.config.id.clone(),
                verb,
            })
        }
    }

    fn selects(&self, secret: &Secret) -> bool {
        self.config
            .select
            .matches_all(&secret.labels, &secret.annotations)
    }

    fn require_unprotected(&self, secret: &Secret) -> Result<(), StoreError> {
        let protect: &Selector = &self.config.protect;
        if protect.matches_any(&secret.labels, &secret.annotations) {
            return Err(StoreError::Protected {
                name: secret.reference(),
                marker: protect
                    .first_match(&secret.labels, &secret.annotations)
                    .unwrap_or_else(|| "a reconciler".to_owned()),
            });
        }
        Ok(())
    }
}
