//! The backends keyway aggregates. Translation only.

pub mod aws;
pub mod gcp;
pub mod k8s;
pub mod own_store;
pub mod yc;

pub use aws::AwsSecretsManager;
pub use gcp::GcpSecretManager;
pub use k8s::KubernetesSecrets;
pub use own_store::PostgresOwnStoreRepo;
pub use yc::YcLockbox;
