//! Rows for the audit log.
//!
//! Translation only, and append-only: there is no update and no delete here.

use crate::domains::audit::AuditRepo;
use crate::domains::audit::entity::{Action, Entry, Record};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::Context as _;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresAuditRepo {
    pool: PgPool,
}

impl PostgresAuditRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct EntryDto {
    id: i64,
    at: DateTime<Utc>,
    actor: String,
    via_token: Option<String>,
    action: String,
    store: String,
    secret: String,
    secret_id: Option<Uuid>,
    version: String,
    keys: Vec<String>,
    subject: String,
    note: String,
}

impl From<EntryDto> for Entry {
    fn from(dto: EntryDto) -> Self {
        Self {
            id: dto.id,
            at: dto.at,
            actor: dto.actor,
            via_token: dto.via_token,
            // A row whose action this build cannot read is reported as it was
            // stored rather than dropped: the log is evidence, and evidence
            // with gaps is worse than evidence with an unfamiliar word in it.
            action: Action::parse(&dto.action).unwrap_or(Action::Update),
            store: dto.store,
            secret: dto.secret,
            secret_id: dto.secret_id,
            version: dto.version,
            keys: dto.keys,
            subject: dto.subject,
            note: dto.note,
        }
    }
}

#[async_trait]
impl AuditRepo for PostgresAuditRepo {
    async fn append(
        &self,
        actor: &str,
        via_token: Option<&str>,
        record: &Record,
    ) -> eyre::Result<()> {
        sqlx::query!(
            "INSERT INTO audit
                (actor, via_token, action, store, secret, secret_id, version, keys, subject, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            actor,
            via_token,
            record.action.as_str(),
            record.store,
            record.secret,
            record.secret_id,
            record.version,
            &record.keys,
            record.subject,
            record.note,
        )
        .execute(&self.pool)
        .await
        .wrap_err("appending an audit entry")?;
        Ok(())
    }

    async fn for_secret(&self, store: &str, secret: &str, limit: i64) -> eyre::Result<Vec<Entry>> {
        let rows = sqlx::query_as!(
            EntryDto,
            "SELECT id, at, actor, via_token, action, store, secret, secret_id, version, keys, subject, note
             FROM audit WHERE store = $1 AND secret = $2
             ORDER BY at DESC, id DESC LIMIT $3",
            store,
            secret,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("reading a secret's history")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn feed(&self, limit: i64, before: Option<i64>) -> eyre::Result<Vec<Entry>> {
        let rows = sqlx::query_as!(
            EntryDto,
            "SELECT id, at, actor, via_token, action, store, secret, secret_id, version, keys, subject, note
             FROM audit WHERE ($2::bigint IS NULL OR id < $2)
             ORDER BY at DESC, id DESC LIMIT $1",
            limit,
            before
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("reading the audit feed")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
