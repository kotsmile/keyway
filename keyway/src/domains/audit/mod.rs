//! What was done, and who did it.
//!
//! Reads are recorded alongside writes, which is unusual and intended: for a
//! secrets tool the interesting question is far more often "who looked at
//! this" than "who changed it".
//!
//! Append-only. There is no update and no delete in this domain.

pub mod entity;
pub mod infra;
pub mod transport;

use async_trait::async_trait;
use entity::{Entry, Record};
use std::sync::Arc;

#[async_trait]
pub trait AuditRepo: Send + Sync + 'static {
    async fn append(
        &self,
        actor: &str,
        via_token: Option<&str>,
        record: &Record,
    ) -> eyre::Result<()>;
    async fn for_secret(&self, store: &str, secret: &str, limit: i64) -> eyre::Result<Vec<Entry>>;
    async fn feed(&self, limit: i64, before: Option<i64>) -> eyre::Result<Vec<Entry>>;
}

pub struct AuditService<R: AuditRepo> {
    repo: Arc<R>,
}

impl<R: AuditRepo> AuditService<R> {
    #[must_use]
    pub fn new(repo: Arc<R>) -> Self {
        Self { repo }
    }

    /// Appends one entry.
    ///
    /// The actor supplies both the handle and, when the request arrived on
    /// one, the token id — taken from the same place, so a caller cannot
    /// record a reveal as somebody else by passing the wrong string.
    ///
    /// # Errors
    ///
    /// When the insert fails.
    pub async fn record(
        &self,
        actor: &crate::domains::identity::entity::Actor,
        record: Record<'_>,
    ) -> eyre::Result<()> {
        self.repo
            .append(actor.handle(), actor.token_id(), &record)
            .await
    }

    /// What has been done to one secret, newest first.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn for_secret(
        &self,
        store: &str,
        secret: &str,
        limit: i64,
    ) -> eyre::Result<Vec<Entry>> {
        self.repo.for_secret(store, secret, limit).await
    }

    /// Everything, newest first.
    ///
    /// Only an admin has any business calling this; the fence is the caller's,
    /// because a repository that decides who may read it is a repository with
    /// two jobs.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn feed(&self, limit: i64, before: Option<i64>) -> eyre::Result<Vec<Entry>> {
        self.repo.feed(limit, before).await
    }
}
