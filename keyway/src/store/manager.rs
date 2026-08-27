use crate::domain::{Metadata, Secret, Version};
use async_trait::async_trait;

/// One backend's driver — the seam that makes keyway an aggregator rather than
/// a front-end for a single secret manager.
///
/// The interface is deliberately small and deliberately CRUD-shaped, because
/// that is the intersection of what secret managers actually agree on: a named
/// secret, an ordered series of immutable versions, and a blob per version.
/// Everything richer — replication policies, leases, rotation schedules — is
/// the backend's business and stays inside its implementation. An interface
/// carrying the union of every backend's features is a union nobody can
/// implement.
///
/// Note what it does NOT know about: key/value. A kv secret is a JSON blob by
/// the time it reaches here, so a backend with native kv can serve it natively
/// and one without is not asked to fake it.
///
/// Implementations must be safe for concurrent use: keyway serves several
/// requests at once and holds one instance per Store for the process's life.
///
/// Implementations do not enforce `allow`, `select` or `protect` — [`super::Store`]
/// does that around them, so no adapter can forget to.
#[async_trait]
pub trait SecretManager: Send + Sync {
    /// Every secret's metadata, no payloads. This is the first screen of the
    /// app, so an implementation should page through the backend rather than
    /// fan out a request per secret.
    async fn list(&self) -> Result<Vec<Secret>, BackendError>;

    /// One secret's metadata.
    async fn get(&self, name: &str) -> Result<Secret, BackendError>;

    /// The revision series, newest first.
    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError>;

    /// One version's payload. `None` means the latest.
    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError>;

    /// Replaces a secret's labels with the map given — replace rather than
    /// merge, because that is what the backends offer. The caller merges.
    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError>;

    /// Makes an empty secret. Split from [`Self::add_version`] because that is
    /// the backends' own shape, and because it lets a create fail on "already
    /// exists" without having first written a payload somewhere.
    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError>;

    /// Writes a new revision and returns it.
    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError>;

    /// Removes the secret and every version of it.
    async fn delete(&self, name: &str) -> Result<(), BackendError>;
}

/// What a backend can fail with.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// No such secret. Kept distinct from every other failure because an
    /// unknown Store id in a URL must be indistinguishable from an unknown
    /// secret, and only the caller of the registry can arrange that.
    #[error("no such secret")]
    NotFound,
    /// The secret exists but this version does not.
    #[error("no such version {0:?}")]
    NoSuchVersion(String),
    /// A name the backend will not accept.
    #[error("invalid name {name:?}: {reason}")]
    InvalidName { name: String, reason: String },
    /// Anything the backend itself reported: a transport failure, a refused
    /// credential, a quota.
    #[error("{context}: {source}")]
    Backend {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl BackendError {
    /// Wraps a backend's own error with a sentence saying what was being done.
    pub fn backend(
        context: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Backend {
            context: context.into(),
            source: source.into(),
        }
    }
}
