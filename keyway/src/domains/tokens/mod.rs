//! The credential for callers that can hold no browser session.
//!
//! External Secrets, CI, the CLI. A token acts as the person who minted it and
//! carries no grants of its own (ADR-0004).

pub mod entity;
pub mod infra;
pub mod transport;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::{Minted, Rejected, StoredToken, Token};
use std::sync::Arc;

/// What this domain needs from storage.
#[async_trait]
pub trait TokenRepo: Send + Sync + 'static {
    async fn insert(&self, token: &StoredToken) -> eyre::Result<DateTime<Utc>>;
    async fn by_id(&self, id: &str) -> eyre::Result<Option<StoredToken>>;
    async fn for_subject(&self, subject: &str) -> eyre::Result<Vec<Token>>;
    async fn delete(&self, subject: &str, id: &str) -> eyre::Result<bool>;
    /// Best-effort: "last used" helps a person decide whether a token is still
    /// needed and is never an authorisation input, so a failure to write it
    /// must not fail a request.
    async fn touch(&self, id: &str, at: DateTime<Utc>);
}

pub struct TokenService<R: TokenRepo> {
    repo: Arc<R>,
}

impl<R: TokenRepo> TokenService<R> {
    #[must_use]
    pub fn new(repo: Arc<R>) -> Self {
        Self { repo }
    }

    /// Mints a token for `subject`. The plaintext is returned once and never
    /// again — only its hash is stored.
    ///
    /// # Errors
    ///
    /// When the name is empty or too long, the random source fails, or the
    /// insert does.
    pub async fn mint(
        &self,
        subject: &str,
        name: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> eyre::Result<Minted> {
        let (stored, plaintext) = entity::mint(subject, name, expires_at)?;
        let created_at = self.repo.insert(&stored).await?;
        Ok(Minted {
            token: Token {
                id: stored.id,
                subject: stored.subject,
                name: stored.name,
                created_at,
                expires_at,
                last_used: None,
            },
            plaintext,
        })
    }

    /// Resolves a presented token to the subject it acts as.
    ///
    /// # Errors
    ///
    /// Only when storage is unreachable. A token that is simply not valid is
    /// `Ok(Err(Rejected))`, because that is an answer rather than a failure.
    pub async fn verify(
        &self,
        presented: &str,
        now: DateTime<Utc>,
    ) -> eyre::Result<Result<Token, Rejected>> {
        let Some((id, secret)) = entity::split(presented) else {
            return Ok(Err(Rejected::Malformed));
        };
        let Some(stored) = self.repo.by_id(id).await? else {
            return Ok(Err(Rejected::Unknown));
        };
        if let Err(rejected) = stored.admits(secret, now) {
            return Ok(Err(rejected));
        }
        self.repo.touch(id, now).await;
        Ok(Ok(Token {
            id: stored.id,
            subject: stored.subject,
            name: stored.name,
            created_at: stored.created_at,
            expires_at: stored.expires_at,
            last_used: stored.last_used,
        }))
    }

    /// The tokens `subject` issued.
    ///
    /// There is deliberately no listing across subjects. An admin can see
    /// every secret because secrets are the thing being administered; a list
    /// of somebody else's credentials is a target, and seeing it would not let
    /// an admin do anything they cannot already do by disabling the account.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn list(&self, subject: &str) -> eyre::Result<Vec<Token>> {
        self.repo.for_subject(subject).await
    }

    /// Revokes one of `subject`'s tokens, returning whether there was one.
    ///
    /// A caller reports "no such token" both for somebody else's and for one
    /// that never existed: confirming that an id names a real token is a fact
    /// nobody has any business learning by guessing.
    ///
    /// # Errors
    ///
    /// When the delete fails.
    pub async fn revoke(&self, subject: &str, id: &str) -> eyre::Result<bool> {
        self.repo.delete(subject, id).await
    }
}
