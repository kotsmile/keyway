//! Rows for grants and ownership.
//!
//! Translation only. Which grant opens what is a rule, and it lives in
//! [`entity::resolve`](crate::domains::access::entity::resolve) — note that
//! nothing here filters by who is asking, because a caller-filtered query
//! would put half the authorisation rule in SQL.

use crate::domains::access::AccessRepo;
use crate::domains::access::entity::{Delegation, Level, Ownership, Subject};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::{Context as _, eyre};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresAccessRepo {
    pool: PgPool,
}

impl PostgresAccessRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct DelegationDto {
    id: Uuid,
    store: String,
    secret: String,
    subject_kind: String,
    subject_id: String,
    level: String,
    keys: Vec<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    note: String,
}

impl TryFrom<DelegationDto> for Delegation {
    type Error = eyre::Error;

    fn try_from(dto: DelegationDto) -> Result<Self, Self::Error> {
        let subject = match dto.subject_kind.as_str() {
            "user" => Subject::User(dto.subject_id),
            "group" => Subject::Group(dto.subject_id),
            other => return Err(eyre!("unknown subject kind {other:?}")),
        };
        Ok(Self {
            id: dto.id,
            store: dto.store,
            secret: dto.secret,
            subject,
            level: dto.level.parse().map_err(|e| eyre!("{e}"))?,
            keys: dto.keys,
            granted_by: dto.granted_by,
            granted_at: dto.granted_at,
            expires_at: dto.expires_at,
            note: dto.note,
        })
    }
}

struct OwnershipDto {
    store: String,
    secret: String,
    owner: String,
    since: DateTime<Utc>,
}

impl From<OwnershipDto> for Ownership {
    fn from(dto: OwnershipDto) -> Self {
        Self {
            store: dto.store,
            secret: dto.secret,
            owner: dto.owner,
            since: dto.since,
        }
    }
}

fn level_word(level: Level) -> &'static str {
    level.as_str()
}

#[async_trait]
impl AccessRepo for PostgresAccessRepo {
    async fn grants_on(&self, store: &str, secret: &str) -> eyre::Result<Vec<Delegation>> {
        let rows = sqlx::query_as!(
            DelegationDto,
            "SELECT id, store, secret, subject_kind, subject_id, level, keys,
                    granted_by, granted_at, expires_at, note
             FROM delegations WHERE store = $1 AND secret = $2
             ORDER BY granted_at",
            store,
            secret
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("reading grants on a secret")?;
        rows.into_iter().map(Delegation::try_from).collect()
    }

    async fn owner_of(&self, store: &str, secret: &str) -> eyre::Result<Option<Ownership>> {
        let row = sqlx::query_as!(
            OwnershipDto,
            "SELECT store, secret, owner, since FROM ownership
             WHERE store = $1 AND secret = $2",
            store,
            secret
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("reading a secret's owner")?;
        Ok(row.map(Into::into))
    }

    async fn grants_for_subjects(&self, subjects: &[Subject]) -> eyre::Result<Vec<Delegation>> {
        // Two arrays rather than a tuple IN, so the kind cannot be matched
        // against the wrong name.
        let kinds: Vec<String> = subjects.iter().map(|s| s.kind().to_owned()).collect();
        let ids: Vec<String> = subjects.iter().map(|s| s.id().to_owned()).collect();

        let rows = sqlx::query_as!(
            DelegationDto,
            "SELECT id, store, secret, subject_kind, subject_id, level, keys,
                    granted_by, granted_at, expires_at, note
             FROM delegations d
             WHERE EXISTS (
                 SELECT 1 FROM unnest($1::text[], $2::text[]) AS want(kind, id)
                 WHERE want.kind = d.subject_kind AND want.id = d.subject_id
             )
             ORDER BY d.store, d.secret",
            &kinds,
            &ids
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("reading grants for a caller")?;
        rows.into_iter().map(Delegation::try_from).collect()
    }

    async fn save_grant(&self, grant: &Delegation) -> eyre::Result<()> {
        sqlx::query!(
            "INSERT INTO delegations
                (id, store, secret, subject_kind, subject_id, level, keys,
                 granted_by, granted_at, expires_at, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (store, secret, subject_kind, subject_id) DO UPDATE SET
                 level = EXCLUDED.level,
                 keys = EXCLUDED.keys,
                 granted_by = EXCLUDED.granted_by,
                 granted_at = EXCLUDED.granted_at,
                 expires_at = EXCLUDED.expires_at,
                 note = EXCLUDED.note",
            grant.id,
            grant.store,
            grant.secret,
            grant.subject.kind(),
            grant.subject.id(),
            level_word(grant.level),
            &grant.keys,
            grant.granted_by,
            grant.granted_at,
            grant.expires_at,
            grant.note,
        )
        .execute(&self.pool)
        .await
        .wrap_err("writing a grant")?;
        Ok(())
    }

    async fn remove_grant(&self, id: Uuid) -> eyre::Result<bool> {
        let done = sqlx::query!("DELETE FROM delegations WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .wrap_err("revoking a grant")?;
        Ok(done.rows_affected() > 0)
    }

    async fn set_owner(&self, ownership: &Ownership) -> eyre::Result<()> {
        // Replaces rather than adds: a transfer changes who is answerable, it
        // does not produce a second owner.
        sqlx::query!(
            "INSERT INTO ownership (store, secret, owner, since)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (store, secret) DO UPDATE SET
                 owner = EXCLUDED.owner,
                 since = EXCLUDED.since",
            ownership.store,
            ownership.secret,
            ownership.owner,
            ownership.since,
        )
        .execute(&self.pool)
        .await
        .wrap_err("recording ownership")?;
        Ok(())
    }
}
