//! Rows for keyway's own Store.
//!
//! Translation only. Which version is current, what a destroyed one yields and
//! how the next number is chosen are rules, and they live in
//! [`entity::own`](crate::domains::secrets::entity::own).

use crate::domains::secrets::entity::{
    Metadata, OwnVersion, Sealed, Secret, Version, VersionState,
};
use crate::domains::secrets::{OwnStoreRepo, SealWith};
use async_trait::async_trait;
use eyre::{Context as _, eyre};
use sqlx::PgPool;
use sqlx::types::Json;

pub struct PostgresOwnStoreRepo {
    pool: PgPool,
}

impl PostgresOwnStoreRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// A secret row, joined to its newest readable version.
struct SecretDto {
    store: String,
    name: String,
    labels: Json<Metadata>,
    annotations: Json<Metadata>,
    latest_version: Option<i64>,
}

impl From<SecretDto> for Secret {
    fn from(dto: SecretDto) -> Self {
        Self {
            store: dto.store,
            name: dto.name,
            labels: dto.labels.0,
            annotations: dto.annotations.0,
            latest_version: dto
                .latest_version
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }
}

/// A version row.
struct VersionDto {
    store: String,
    name: String,
    version: i64,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key_id: String,
    state: String,
}

impl From<VersionDto> for OwnVersion {
    fn from(dto: VersionDto) -> Self {
        Self {
            store: dto.store,
            secret: dto.name,
            number: dto.version,
            sealed: Sealed {
                key_id: dto.key_id,
                nonce: dto.nonce,
                ciphertext: dto.ciphertext,
            },
            state: state_from(&dto.state),
        }
    }
}

/// An unrecognised state reads as destroyed rather than enabled: a build that
/// does not understand what a row says must not offer to reveal it.
fn state_from(word: &str) -> VersionState {
    match word {
        "enabled" => VersionState::Enabled,
        "disabled" => VersionState::Disabled,
        _ => VersionState::Destroyed,
    }
}

fn state_word(state: VersionState) -> &'static str {
    match state {
        VersionState::Enabled => "enabled",
        VersionState::Disabled => "disabled",
        VersionState::Destroyed => "destroyed",
    }
}

#[async_trait]
impl OwnStoreRepo for PostgresOwnStoreRepo {
    async fn list_secrets(&self, store: &str) -> eyre::Result<Vec<Secret>> {
        let rows = sqlx::query_as!(
            SecretDto,
            r#"SELECT s.store, s.name,
                      s.labels as "labels: Json<Metadata>",
                      s.annotations as "annotations: Json<Metadata>",
                      (SELECT v.version FROM own_versions v
                        WHERE v.store = s.store AND v.name = s.name AND v.state = 'enabled'
                        ORDER BY v.version DESC LIMIT 1) as "latest_version"
               FROM own_secrets s WHERE s.store = $1 ORDER BY s.name"#,
            store
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("listing secrets")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_secret(&self, store: &str, name: &str) -> eyre::Result<Option<Secret>> {
        let row = sqlx::query_as!(
            SecretDto,
            r#"SELECT s.store, s.name,
                      s.labels as "labels: Json<Metadata>",
                      s.annotations as "annotations: Json<Metadata>",
                      (SELECT v.version FROM own_versions v
                        WHERE v.store = s.store AND v.name = s.name AND v.state = 'enabled'
                        ORDER BY v.version DESC LIMIT 1) as "latest_version"
               FROM own_secrets s WHERE s.store = $1 AND s.name = $2"#,
            store,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("reading a secret")?;
        Ok(row.map(Into::into))
    }

    async fn insert_secret(&self, secret: &Secret) -> eyre::Result<()> {
        sqlx::query!(
            "INSERT INTO own_secrets (store, name, labels, annotations)
             VALUES ($1, $2, $3, $4)",
            secret.store,
            secret.name,
            serde_json::to_value(&secret.labels)?,
            serde_json::to_value(&secret.annotations)?,
        )
        .execute(&self.pool)
        .await
        .wrap_err("creating a secret")?;
        Ok(())
    }

    async fn update_labels(
        &self,
        store: &str,
        name: &str,
        labels: &Metadata,
    ) -> eyre::Result<bool> {
        let done = sqlx::query!(
            "UPDATE own_secrets SET labels = $3 WHERE store = $1 AND name = $2",
            store,
            name,
            serde_json::to_value(labels)?,
        )
        .execute(&self.pool)
        .await
        .wrap_err("setting labels")?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_secret(&self, store: &str, name: &str) -> eyre::Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM own_secrets WHERE store = $1 AND name = $2",
            store,
            name
        )
        .execute(&self.pool)
        .await
        .wrap_err("deleting a secret")?;
        Ok(done.rows_affected() > 0)
    }

    async fn list_versions(&self, store: &str, name: &str) -> eyre::Result<Vec<Version>> {
        let rows = sqlx::query!(
            "SELECT version, state FROM own_versions
             WHERE store = $1 AND name = $2 ORDER BY version DESC",
            store,
            name
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("listing versions")?;

        Ok(rows
            .into_iter()
            .map(|row| Version {
                id: row.version.to_string(),
                state: state_from(&row.state),
            })
            .collect())
    }

    async fn get_version(
        &self,
        store: &str,
        name: &str,
        number: i64,
    ) -> eyre::Result<Option<OwnVersion>> {
        let row = sqlx::query_as!(
            VersionDto,
            "SELECT store, name, version, ciphertext, nonce, key_id, state
             FROM own_versions WHERE store = $1 AND name = $2 AND version = $3",
            store,
            name,
            number
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("reading a version")?;
        Ok(row.map(Into::into))
    }

    async fn append_version(
        &self,
        store: &str,
        name: &str,
        seal: SealWith<'_>,
    ) -> eyre::Result<OwnVersion> {
        let mut tx = self.pool.begin().await.wrap_err("starting a transaction")?;

        // Locking the secret row is what serialises two concurrent writers.
        // The number is bound into the seal, so allocating it outside this
        // transaction would let them seal different payloads under one number.
        sqlx::query!(
            "SELECT store FROM own_secrets WHERE store = $1 AND name = $2 FOR UPDATE",
            store,
            name
        )
        .fetch_optional(&mut *tx)
        .await
        .wrap_err("locking a secret")?;

        let existing = sqlx::query!(
            "SELECT coalesce(max(version), 0) as \"highest!\" FROM own_versions
             WHERE store = $1 AND name = $2",
            store,
            name
        )
        .fetch_one(&mut *tx)
        .await
        .wrap_err("allocating a version")?;

        let version = seal(existing.highest + 1).map_err(|e| eyre!(e))?;

        sqlx::query!(
            "INSERT INTO own_versions (store, name, version, ciphertext, nonce, key_id, state)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            version.store,
            version.secret,
            version.number,
            version.sealed.ciphertext,
            version.sealed.nonce,
            version.sealed.key_id,
            state_word(version.state),
        )
        .execute(&mut *tx)
        .await
        .wrap_err("writing a version")?;

        tx.commit().await.wrap_err("committing a version")?;
        Ok(version)
    }

    async fn key_ids_in_use(&self, store: &str) -> eyre::Result<Vec<String>> {
        let rows = sqlx::query!(
            "SELECT DISTINCT key_id FROM own_versions
             WHERE store = $1 AND state <> 'destroyed' ORDER BY key_id",
            store
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("listing keys in use")?;
        Ok(rows.into_iter().map(|row| row.key_id).collect())
    }
}
