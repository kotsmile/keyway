//! The inventory, and the seam over whatever holds it.

pub mod entity;
pub mod infra;
pub mod transport;

use async_trait::async_trait;
use entity::{BackendError, Keyring, Metadata, OwnVersion, Secret, SecretManager, Version};
use std::sync::Arc;

/// Everything keyway's own Store needs from storage.
///
/// It speaks in entities, not columns: the rules about which version is
/// current, what a destroyed one yields and how the next number is chosen live
/// in [`entity::own`], and this trait only moves them.
#[async_trait]
pub trait OwnStoreRepo: Send + Sync + 'static {
    async fn list_secrets(&self, store: &str) -> eyre::Result<Vec<Secret>>;
    async fn get_secret(&self, store: &str, name: &str) -> eyre::Result<Option<Secret>>;
    async fn insert_secret(&self, secret: &Secret) -> eyre::Result<()>;
    async fn update_labels(&self, store: &str, name: &str, labels: &Metadata)
    -> eyre::Result<bool>;
    async fn delete_secret(&self, store: &str, name: &str) -> eyre::Result<bool>;

    async fn list_versions(&self, store: &str, name: &str) -> eyre::Result<Vec<Version>>;
    async fn get_version(
        &self,
        store: &str,
        name: &str,
        number: i64,
    ) -> eyre::Result<Option<OwnVersion>>;
    /// Allocates the next number and writes the version the callback seals
    /// under it, in one transaction.
    ///
    /// The number and the seal have to agree, because the number is bound into
    /// the tag — so allocating it outside the write would let two concurrent
    /// writers seal different payloads under one number.
    async fn append_version(
        &self,
        store: &str,
        name: &str,
        seal: SealWith<'_>,
    ) -> eyre::Result<OwnVersion>;

    async fn key_ids_in_use(&self, store: &str) -> eyre::Result<Vec<String>>;
}

/// Seals a payload once the version number is known.
pub type SealWith<'a> = &'a (dyn Fn(i64) -> Result<OwnVersion, BackendError> + Send + Sync);

/// keyway's own Store.
///
/// Exists so keyway runs with no cloud account at all, which is what makes a
/// one-command quickstart possible — and it is why the key comes from config
/// rather than an unseal flow: keyway is a dependency of other people's
/// deployments, and a service needing a human present after every node
/// eviction blocks deploys at 3am.
pub struct OwnStoreService<R: OwnStoreRepo> {
    store_id: String,
    repo: Arc<R>,
    keyring: Keyring,
}

impl<R: OwnStoreRepo> OwnStoreService<R> {
    #[must_use]
    pub fn new(store_id: impl Into<String>, repo: Arc<R>, keyring: Keyring) -> Self {
        Self {
            store_id: store_id.into(),
            repo,
            keyring,
        }
    }

    /// Which key ids still have a version sealed under them.
    ///
    /// A rotation is finished when this returns only the active id. Dropping a
    /// key before then is exactly what makes a payload unopenable, so this is
    /// the question an operator needs answered before they do it.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn keys_in_use(&self) -> eyre::Result<Vec<String>> {
        self.repo.key_ids_in_use(&self.store_id).await
    }

    async fn require_exists(&self, name: &str) -> Result<Secret, BackendError> {
        self.repo
            .get_secret(&self.store_id, name)
            .await
            .map_err(|e| BackendError::backend("looking up a secret", e))?
            .ok_or(BackendError::NotFound)
    }
}

fn backend(context: &'static str) -> impl FnOnce(eyre::Report) -> BackendError {
    move |e| BackendError::backend(context, e)
}

#[async_trait]
impl<R: OwnStoreRepo> SecretManager for OwnStoreService<R> {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        self.repo
            .list_secrets(&self.store_id)
            .await
            .map_err(backend("listing secrets"))
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        self.require_exists(name).await
    }

    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        self.require_exists(name).await?;
        self.repo
            .list_versions(&self.store_id, name)
            .await
            .map_err(backend("listing versions"))
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        self.require_exists(name).await?;

        let number = if let Some(raw) = version {
            entity::own::parse_number(raw)?
        } else {
            let versions = self
                .repo
                .list_versions(&self.store_id, name)
                .await
                .map_err(backend("resolving the latest version"))?;
            entity::own::latest(&versions)
                .ok_or_else(|| BackendError::NoSuchVersion("latest".to_owned()))
                .and_then(|v| entity::own::parse_number(&v.id))?
        };

        self.repo
            .get_version(&self.store_id, name, number)
            .await
            .map_err(backend("reading a version"))?
            .ok_or_else(|| BackendError::NoSuchVersion(number.to_string()))?
            .open(&self.keyring)
    }

    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let changed = self
            .repo
            .update_labels(&self.store_id, name, &labels)
            .await
            .map_err(backend("setting labels"))?;
        if changed {
            Ok(())
        } else {
            Err(BackendError::NotFound)
        }
    }

    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        if name.is_empty() {
            return Err(BackendError::InvalidName {
                name: name.to_owned(),
                reason: "a name is required".to_owned(),
            });
        }
        self.repo
            .insert_secret(&Secret {
                store: self.store_id.clone(),
                name: name.to_owned(),
                labels,
                annotations: Metadata::new(),
                latest_version: String::new(),
            })
            .await
            .map_err(backend("creating a secret"))
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        self.require_exists(name).await?;

        let keyring = &self.keyring;
        let store = self.store_id.clone();
        let secret = name.to_owned();
        let payload = payload.to_vec();
        let seal = move |number: i64| OwnVersion::seal(keyring, &store, &secret, number, &payload);

        let written = self
            .repo
            .append_version(&self.store_id, name, &seal)
            .await
            .map_err(backend("writing a version"))?;
        Ok(written.describe())
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        let removed = self
            .repo
            .delete_secret(&self.store_id, name)
            .await
            .map_err(backend("deleting a secret"))?;
        if removed {
            Ok(())
        } else {
            Err(BackendError::NotFound)
        }
    }
}
