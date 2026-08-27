//! Who is asking, and what keyway remembers about them.

pub mod entity;
pub mod infra;
pub mod transport;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::{Actor, RememberedUser, Role};
use std::sync::Arc;

/// What this domain needs from storage: the groups claim as it stood at a
/// person's last sign-in.
#[async_trait]
pub trait IdentityRepo: Send + Sync + 'static {
    async fn remember(&self, user: &RememberedUser) -> eyre::Result<()>;
    async fn recall(&self, handle: &str) -> eyre::Result<Option<RememberedUser>>;
}

/// A live connection to the identity provider.
///
/// Optional by design (ADR-0004): configured, it replaces remembered groups
/// with a live answer and adds an account-enabled check. Unconfigured, keyway
/// calls no identity provider on any request.
#[async_trait]
pub trait Directory: Send + Sync + 'static {
    async fn resolve(&self, handle: &str) -> eyre::Result<Option<DirectoryAnswer>>;
}

/// What a Directory says about somebody right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryAnswer {
    pub enabled: bool,
    pub groups: Vec<String>,
}

pub struct IdentityService<R: IdentityRepo> {
    repo: Arc<R>,
    directory: Option<Arc<dyn Directory>>,
}

impl<R: IdentityRepo> IdentityService<R> {
    #[must_use]
    pub fn new(repo: Arc<R>, directory: Option<Arc<dyn Directory>>) -> Self {
        Self { repo, directory }
    }

    /// Records a sign-in. The groups are REPLACED, never merged: somebody
    /// removed from a team must lose it here on their next sign-in.
    ///
    /// # Errors
    ///
    /// When the write fails.
    pub async fn sign_in(
        &self,
        handle: &str,
        groups: Vec<String>,
        email: &str,
        name: &str,
        at: DateTime<Utc>,
    ) -> eyre::Result<()> {
        self.repo
            .remember(&RememberedUser {
                handle: handle.to_owned(),
                groups,
                email: email.to_owned(),
                name: name.to_owned(),
                last_login: at,
            })
            .await
    }

    /// The actor a token acts as.
    ///
    /// With a Directory configured the groups are live and a disabled account
    /// resolves to nothing — which is what buys back "disable the account and
    /// every token it issued dies". Without one, they are what was remembered
    /// at the last sign-in.
    ///
    /// # Errors
    ///
    /// When the lookup fails.
    pub async fn actor_for_token(
        &self,
        handle: &str,
        roles: Vec<Role>,
        token_id: &str,
    ) -> eyre::Result<Option<Actor>> {
        let groups = match &self.directory {
            Some(directory) => match directory.resolve(handle).await? {
                Some(answer) if answer.enabled => answer.groups,
                // Disabled, or gone from the directory entirely.
                _ => return Ok(None),
            },
            None => self
                .repo
                .recall(handle)
                .await?
                .map(|user| user.groups)
                .unwrap_or_default(),
        };
        Ok(Some(Actor::new(handle, groups, roles).via_token(token_id)))
    }

    /// What was remembered, or `None` if they have never signed in.
    ///
    /// # Errors
    ///
    /// When the query fails.
    pub async fn recall(&self, handle: &str) -> eyre::Result<Option<RememberedUser>> {
        self.repo.recall(handle).await
    }

    /// Whether a Directory is configured — what the console shows when
    /// delegating to a group, since without one an API token cannot see the
    /// grant.
    #[must_use]
    pub fn has_directory(&self) -> bool {
        self.directory.is_some()
    }
}
