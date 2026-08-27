//! keyway's own Store.
//!
//! The one backend where keyway holds a payload rather than pointing at
//! somebody else's. It exists so keyway runs with no cloud account at all,
//! which is what makes a one-command quickstart possible — and it is why the
//! key comes from config rather than from an unseal flow: keyway is a
//! dependency of other people's deployments, and a service needing a human
//! present after every node eviction blocks deploys at 3am.

mod crypto;

pub use crypto::{Error as CryptoError, Keyring, Sealed};

use crate::domain::{Metadata, Secret, Version, VersionState};
use crate::store::{BackendError, SecretManager};
use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::types::Json;

/// keyway's own Store, over keyway's own Postgres.
pub struct OwnStore {
    store_id: String,
    pool: PgPool,
    keyring: Keyring,
}

impl OwnStore {
    #[must_use]
    pub fn new(store_id: impl Into<String>, pool: PgPool, keyring: Keyring) -> Self {
        Self {
            store_id: store_id.into(),
            pool,
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
    pub async fn keys_in_use(&self) -> Result<Vec<String>, BackendError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT key_id FROM own_versions
             WHERE store = $1 AND state <> 'destroyed' ORDER BY key_id",
        )
        .bind(&self.store_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BackendError::backend("listing keys in use", e))?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn resolve_version(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<i64, BackendError> {
        if let Some(raw) = version {
            return raw
                .parse()
                .map_err(|_| BackendError::NoSuchVersion(raw.to_owned()));
        }
        let latest: Option<(i64,)> = sqlx::query_as(
            "SELECT version FROM own_versions
             WHERE store = $1 AND name = $2 AND state = 'enabled'
             ORDER BY version DESC LIMIT 1",
        )
        .bind(&self.store_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BackendError::backend("resolving the latest version", e))?;
        latest
            .map(|(v,)| v)
            .ok_or_else(|| BackendError::NoSuchVersion("latest".to_owned()))
    }

    async fn require_exists(&self, name: &str) -> Result<(), BackendError> {
        let found: Option<(String,)> =
            sqlx::query_as("SELECT name FROM own_secrets WHERE store = $1 AND name = $2")
                .bind(&self.store_id)
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| BackendError::backend("looking up a secret", e))?;
        found.map(|_| ()).ok_or(BackendError::NotFound)
    }
}

/// One secret as the tables hold it, joined to its newest enabled version.
type SecretRow = (String, Json<Metadata>, Json<Metadata>, Option<i64>);

fn into_secret(store: &str, row: SecretRow) -> Secret {
    let (name, labels, annotations, latest) = row;
    Secret {
        store: store.to_owned(),
        name,
        labels: labels.0,
        annotations: annotations.0,
        latest_version: latest.map(|v| v.to_string()).unwrap_or_default(),
    }
}

const SELECT_SECRETS: &str = "SELECT s.name, s.labels, s.annotations,
        (SELECT v.version FROM own_versions v
          WHERE v.store = s.store AND v.name = s.name AND v.state = 'enabled'
          ORDER BY v.version DESC LIMIT 1)
     FROM own_secrets s WHERE s.store = $1";

const SELECT_ONE_SECRET: &str = "SELECT s.name, s.labels, s.annotations,
        (SELECT v.version FROM own_versions v
          WHERE v.store = s.store AND v.name = s.name AND v.state = 'enabled'
          ORDER BY v.version DESC LIMIT 1)
     FROM own_secrets s WHERE s.store = $1 AND s.name = $2";

#[async_trait]
impl SecretManager for OwnStore {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        let rows: Vec<SecretRow> = sqlx::query_as(SELECT_SECRETS)
            .bind(&self.store_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BackendError::backend("listing secrets", e))?;
        Ok(rows
            .into_iter()
            .map(|row| into_secret(&self.store_id, row))
            .collect())
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        let row: Option<SecretRow> = sqlx::query_as(SELECT_ONE_SECRET)
            .bind(&self.store_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| BackendError::backend("reading a secret", e))?;
        row.map(|row| into_secret(&self.store_id, row))
            .ok_or(BackendError::NotFound)
    }

    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        self.require_exists(name).await?;
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT version, state FROM own_versions
             WHERE store = $1 AND name = $2 ORDER BY version DESC",
        )
        .bind(&self.store_id)
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BackendError::backend("listing versions", e))?;

        Ok(rows
            .into_iter()
            .map(|(version, state)| Version {
                id: version.to_string(),
                state: match state.as_str() {
                    "disabled" => VersionState::Disabled,
                    "destroyed" => VersionState::Destroyed,
                    _ => VersionState::Enabled,
                },
            })
            .collect())
    }

    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        self.require_exists(name).await?;
        let wanted = self.resolve_version(name, version).await?;

        let row: Option<(Vec<u8>, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT ciphertext, nonce, key_id, state FROM own_versions
             WHERE store = $1 AND name = $2 AND version = $3",
        )
        .bind(&self.store_id)
        .bind(name)
        .bind(wanted)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BackendError::backend("reading a version", e))?;

        let (ciphertext, nonce, key_id, state) =
            row.ok_or_else(|| BackendError::NoSuchVersion(wanted.to_string()))?;

        // A destroyed version has no payload to reveal, and saying so is
        // better than handing back whatever bytes the row still holds.
        if state == "destroyed" {
            return Err(BackendError::NoSuchVersion(wanted.to_string()));
        }

        let sealed = Sealed {
            key_id,
            nonce,
            ciphertext,
        };
        let aad = crypto::aad(&self.store_id, name, &wanted.to_string());
        let opened = self
            .keyring
            .open(&sealed, &aad)
            .map_err(|e| BackendError::backend("opening a sealed payload", e))?;
        Ok(opened.to_vec())
    }

    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        let done = sqlx::query("UPDATE own_secrets SET labels = $3 WHERE store = $1 AND name = $2")
            .bind(&self.store_id)
            .bind(name)
            .bind(Json(labels))
            .execute(&self.pool)
            .await
            .map_err(|e| BackendError::backend("setting labels", e))?;
        if done.rows_affected() == 0 {
            return Err(BackendError::NotFound);
        }
        Ok(())
    }

    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        if name.is_empty() {
            return Err(BackendError::InvalidName {
                name: name.to_owned(),
                reason: "a name is required".to_owned(),
            });
        }
        sqlx::query("INSERT INTO own_secrets (store, name, labels) VALUES ($1, $2, $3)")
            .bind(&self.store_id)
            .bind(name)
            .bind(Json(labels))
            .execute(&self.pool)
            .await
            .map_err(|e| BackendError::backend("creating a secret", e))?;
        Ok(())
    }

    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        self.require_exists(name).await?;

        // The version number and the seal must agree, because the number is
        // bound into the tag. Allocating it inside the transaction is what
        // stops two concurrent writers sealing different payloads under one
        // number.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| BackendError::backend("starting a transaction", e))?;

        sqlx::query("SELECT 1 FROM own_secrets WHERE store = $1 AND name = $2 FOR UPDATE")
            .bind(&self.store_id)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| BackendError::backend("locking a secret", e))?;

        let (next,): (i64,) = sqlx::query_as(
            "SELECT coalesce(max(version), 0) + 1 FROM own_versions
             WHERE store = $1 AND name = $2",
        )
        .bind(&self.store_id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| BackendError::backend("allocating a version", e))?;

        let aad = crypto::aad(&self.store_id, name, &next.to_string());
        let sealed = self
            .keyring
            .seal(payload, &aad)
            .map_err(|e| BackendError::backend("sealing a payload", e))?;

        sqlx::query(
            "INSERT INTO own_versions (store, name, version, ciphertext, nonce, key_id)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&self.store_id)
        .bind(name)
        .bind(next)
        .bind(&sealed.ciphertext)
        .bind(&sealed.nonce)
        .bind(&sealed.key_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| BackendError::backend("writing a version", e))?;

        tx.commit()
            .await
            .map_err(|e| BackendError::backend("committing a version", e))?;

        Ok(Version {
            id: next.to_string(),
            state: VersionState::Enabled,
        })
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        let done = sqlx::query("DELETE FROM own_secrets WHERE store = $1 AND name = $2")
            .bind(&self.store_id)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| BackendError::backend("deleting a secret", e))?;
        if done.rows_affected() == 0 {
            return Err(BackendError::NotFound);
        }
        Ok(())
    }
}
