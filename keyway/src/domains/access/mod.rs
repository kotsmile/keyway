//! Who may see what.
//!
//! The rules live in [`entity`] and touch nothing: [`entity::resolve`] is the
//! whole authorisation test, and it takes the grants it is given rather than
//! fetching them. The service below is the thin part — it loads, asks, and
//! writes.

pub mod entity;
pub mod infra;
pub mod transport;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::{Access, Delegation, Level, Ownership, Subject};
use std::sync::Arc;
use uuid::Uuid;

/// Everything this domain needs from storage.
///
/// Note what is absent: any method taking a caller. Filtering grants by who is
/// asking would put half the authorisation rule in SQL, where the next person
/// to write a query is free to get it wrong — so the repository answers "what
/// grants exist on this secret" and [`entity::resolve`] answers the rest.
#[async_trait]
pub trait AccessRepo: Send + Sync + 'static {
    async fn grants_on(&self, store: &str, secret: &str) -> eyre::Result<Vec<Delegation>>;
    async fn owner_of(&self, store: &str, secret: &str) -> eyre::Result<Option<Ownership>>;
    async fn grants_for_subjects(&self, subjects: &[Subject]) -> eyre::Result<Vec<Delegation>>;
    async fn save_grant(&self, grant: &Delegation) -> eyre::Result<()>;
    async fn remove_grant(&self, id: Uuid) -> eyre::Result<bool>;
    async fn set_owner(&self, ownership: &Ownership) -> eyre::Result<()>;
}

pub struct AccessService<R: AccessRepo> {
    repo: Arc<R>,
}

impl<R: AccessRepo> AccessService<R> {
    #[must_use]
    pub fn new(repo: Arc<R>) -> Self {
        Self { repo }
    }

    /// How far `actor` gets on one secret.
    ///
    /// # Errors
    ///
    /// When the grants or the owner cannot be read.
    pub async fn access_for(
        &self,
        actor: &crate::domains::identity::entity::Actor,
        store: &str,
        secret: &str,
        now: DateTime<Utc>,
    ) -> eyre::Result<Access> {
        let owner = self.repo.owner_of(store, secret).await?;
        let grants = self.repo.grants_on(store, secret).await?;
        Ok(entity::resolve(actor, owner.as_ref(), &grants, now))
    }

    /// Every grant on one secret — the list that answers "who can see this".
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn grants_on(&self, store: &str, secret: &str) -> eyre::Result<Vec<Delegation>> {
        self.repo.grants_on(store, secret).await
    }

    /// Who owns a secret, if anybody does.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn owner_of(&self, store: &str, secret: &str) -> eyre::Result<Option<Ownership>> {
        self.repo.owner_of(store, secret).await
    }

    /// Every grant addressed to this caller, across every secret — what a
    /// listing is narrowed by.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn grants_for(
        &self,
        actor: &crate::domains::identity::entity::Actor,
    ) -> eyre::Result<Vec<Delegation>> {
        self.repo.grants_for_subjects(&actor.subjects()).await
    }

    /// Writes a grant.
    ///
    /// # Errors
    ///
    /// When the write fails.
    pub async fn delegate(&self, grant: &Delegation) -> eyre::Result<()> {
        self.repo.save_grant(grant).await
    }

    /// Removes one. Returns whether there was one to remove.
    ///
    /// # Errors
    ///
    /// When the delete fails.
    pub async fn revoke(&self, id: Uuid) -> eyre::Result<bool> {
        self.repo.remove_grant(id).await
    }

    /// Records who owns a secret. Replaces rather than adds: a transfer
    /// changes who is answerable, it does not produce a second owner.
    ///
    /// # Errors
    ///
    /// When the write fails.
    pub async fn set_owner(&self, ownership: &Ownership) -> eyre::Result<()> {
        self.repo.set_owner(ownership).await
    }

    /// Whether `actor` may do `wanted` to this secret.
    ///
    /// # Errors
    ///
    /// When the grants cannot be read.
    pub async fn allows(
        &self,
        actor: &crate::domains::identity::entity::Actor,
        store: &str,
        secret: &str,
        wanted: Level,
        now: DateTime<Utc>,
    ) -> eyre::Result<bool> {
        Ok(self
            .access_for(actor, store, secret, now)
            .await?
            .allows(wanted))
    }
}
