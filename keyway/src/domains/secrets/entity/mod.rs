//! The inventory's rules. Nothing here talks to a backend or a database.

pub mod crypto;
pub mod identity;
mod manager;
pub mod own;
mod registry;
mod secret;
mod store;
#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

pub use crypto::{Error as CryptoError, Keyring, Sealed};
pub use identity::{LABEL as ID_LABEL, id_for, id_of};
pub use manager::{BackendError, SecretManager};
pub use own::OwnVersion;
pub use registry::{Registry, RegistryError};
pub use secret::{Metadata, Secret, Version, VersionState};
pub use store::{Store, StoreError};
