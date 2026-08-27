//! Rows for issued tokens.
//!
//! Translation only. What makes a presented token acceptable is a rule, and it
//! lives in [`entity`](crate::domains::tokens::entity).

use crate::domains::tokens::TokenRepo;
use crate::domains::tokens::entity::{StoredToken, Token};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::Context as _;
use sqlx::PgPool;

pub struct PostgresTokenRepo {
    pool: PgPool,
}

impl PostgresTokenRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct TokenDto {
    id: String,
    hash: Vec<u8>,
    subject: String,
    name: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
}

impl From<TokenDto> for StoredToken {
    fn from(dto: TokenDto) -> Self {
        Self {
            id: dto.id,
            hash: dto.hash,
            subject: dto.subject,
            name: dto.name,
            created_at: dto.created_at,
            expires_at: dto.expires_at,
            last_used: dto.last_used,
        }
    }
}

#[async_trait]
impl TokenRepo for PostgresTokenRepo {
    async fn insert(&self, token: &StoredToken) -> eyre::Result<DateTime<Utc>> {
        let row = sqlx::query!(
            "INSERT INTO tokens (id, hash, subject, name, expires_at)
             VALUES ($1, $2, $3, $4, $5) RETURNING created_at",
            token.id,
            token.hash,
            token.subject,
            token.name,
            token.expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .wrap_err("minting a token")?;
        Ok(row.created_at)
    }

    async fn by_id(&self, id: &str) -> eyre::Result<Option<StoredToken>> {
        let row = sqlx::query_as!(
            TokenDto,
            "SELECT id, hash, subject, name, created_at, expires_at, last_used
             FROM tokens WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("looking up a token")?;
        Ok(row.map(Into::into))
    }

    async fn for_subject(&self, subject: &str) -> eyre::Result<Vec<Token>> {
        let rows = sqlx::query!(
            "SELECT id, name, created_at, expires_at, last_used
             FROM tokens WHERE subject = $1 ORDER BY created_at DESC",
            subject
        )
        .fetch_all(&self.pool)
        .await
        .wrap_err("listing tokens")?;

        Ok(rows
            .into_iter()
            .map(|row| Token {
                id: row.id,
                subject: subject.to_owned(),
                name: row.name,
                created_at: row.created_at,
                expires_at: row.expires_at,
                last_used: row.last_used,
            })
            .collect())
    }

    async fn delete(&self, subject: &str, id: &str) -> eyre::Result<bool> {
        // Scoped to the subject in the statement rather than in a check before
        // it, so there is no window between deciding and doing.
        let done = sqlx::query!(
            "DELETE FROM tokens WHERE subject = $1 AND id = $2",
            subject,
            id
        )
        .execute(&self.pool)
        .await
        .wrap_err("revoking a token")?;
        Ok(done.rows_affected() > 0)
    }

    async fn touch(&self, id: &str, at: DateTime<Utc>) {
        // Best-effort by construction: the result is discarded. "Last used" is
        // a convenience for the person deciding whether a token is still
        // needed, never an authorisation input.
        let _ = sqlx::query!("UPDATE tokens SET last_used = $2 WHERE id = $1", id, at)
            .execute(&self.pool)
            .await;
    }
}
