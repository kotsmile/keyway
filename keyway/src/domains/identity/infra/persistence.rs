//! What keyway remembers about a person between sign-ins.
//!
//! An API token carries no claim, so without this it could not know which
//! groups its holder is in — and a grant to a team would be invisible to every
//! bot and every CI job (ADR-0004).
//!
//! Remembered, not frozen: every sign-in refreshes it. Minting a token goes
//! through a browser session, so a token's remembered groups are never empty.

use crate::domains::identity::IdentityRepo;
use crate::domains::identity::entity::RememberedUser;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::Context as _;
use sqlx::PgPool;

pub struct PostgresIdentityRepo {
    pool: PgPool,
}

impl PostgresIdentityRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IdentityRepo for PostgresIdentityRepo {
    async fn remember(&self, user: &RememberedUser) -> eyre::Result<()> {
        // Groups are REPLACED rather than merged. A person removed from a team
        // must lose it on their next sign-in; a merge would mean membership
        // only ever grew.
        sqlx::query(
            "INSERT INTO users (handle, groups, email, name, last_login)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (handle) DO UPDATE SET
                 groups = EXCLUDED.groups,
                 email = EXCLUDED.email,
                 name = EXCLUDED.name,
                 last_login = EXCLUDED.last_login",
        )
        .bind(&user.handle)
        .bind(&user.groups)
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.last_login)
        .execute(&self.pool)
        .await
        .wrap_err("remembering a sign-in")?;
        Ok(())
    }

    async fn recall(&self, handle: &str) -> eyre::Result<Option<RememberedUser>> {
        let row: Option<(Vec<String>, String, String, DateTime<Utc>)> =
            sqlx::query_as("SELECT groups, email, name, last_login FROM users WHERE handle = $1")
                .bind(handle)
                .fetch_optional(&self.pool)
                .await
                .wrap_err("recalling a user")?;

        Ok(row.map(|(groups, email, name, last_login)| RememberedUser {
            handle: handle.to_owned(),
            groups,
            email,
            name,
            last_login,
        }))
    }
}
