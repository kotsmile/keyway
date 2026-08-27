//! keyway's own Store, as rules.
//!
//! The one backend where keyway holds a payload rather than pointing at
//! somebody else's. Everything here decides things; nothing here talks to a
//! database. What a row looks like is [`infra`](crate::domains::secrets::infra)'s
//! business.

use super::crypto::{self, Keyring, Sealed};
use super::{BackendError, Version, VersionState};

/// One stored revision of a secret in keyway's own Store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnVersion {
    pub store: String,
    pub secret: String,
    /// Per secret and monotonic. Bound into the seal, so it and the payload
    /// cannot drift apart.
    pub number: i64,
    pub sealed: Sealed,
    pub state: VersionState,
}

impl OwnVersion {
    /// Seals `payload` as the next version of a secret.
    ///
    /// # Errors
    ///
    /// When sealing fails.
    pub fn seal(
        keyring: &Keyring,
        store: &str,
        secret: &str,
        number: i64,
        payload: &[u8],
    ) -> Result<Self, BackendError> {
        let sealed = keyring
            .seal(payload, &Self::aad(store, secret, number))
            .map_err(|e| BackendError::backend("sealing a payload", e))?;
        Ok(Self {
            store: store.to_owned(),
            secret: secret.to_owned(),
            number,
            sealed,
            state: VersionState::Enabled,
        })
    }

    /// Opens this version's payload.
    ///
    /// # Errors
    ///
    /// [`BackendError::NoSuchVersion`] for a destroyed version — its payload
    /// is gone for good, and saying so is better than handing back whatever
    /// bytes a row still holds. Otherwise when the key is not configured or
    /// the payload does not authenticate.
    pub fn open(&self, keyring: &Keyring) -> Result<Vec<u8>, BackendError> {
        if self.state == VersionState::Destroyed {
            return Err(BackendError::NoSuchVersion(self.number.to_string()));
        }
        let opened = keyring
            .open(
                &self.sealed,
                &Self::aad(&self.store, &self.secret, self.number),
            )
            .map_err(|e| BackendError::backend("opening a sealed payload", e))?;
        Ok(opened.to_vec())
    }

    /// How this version reports itself to the rest of the system.
    #[must_use]
    pub fn describe(&self) -> Version {
        Version {
            id: self.number.to_string(),
            state: self.state,
        }
    }

    /// The identity bound into the tag, so a ciphertext lifted from one row
    /// into another fails to open rather than revealing the wrong value.
    fn aad(store: &str, secret: &str, number: i64) -> Vec<u8> {
        crypto::aad(store, secret, &number.to_string())
    }
}

/// Which version an unqualified read resolves to: the newest that still has a
/// payload.
#[must_use]
pub fn latest(versions: &[Version]) -> Option<&Version> {
    versions
        .iter()
        .filter(|v| v.state == VersionState::Enabled)
        .max_by_key(|v| v.id.parse::<i64>().unwrap_or(i64::MIN))
}

/// The number the next version takes.
///
/// Derived from what exists rather than from a sequence, because the number is
/// bound into the seal: the caller allocates and seals inside one transaction,
/// so two concurrent writers cannot seal different payloads under one number.
#[must_use]
pub fn next_number(versions: &[Version]) -> i64 {
    versions
        .iter()
        .filter_map(|v| v.id.parse::<i64>().ok())
        .max()
        .unwrap_or(0)
        + 1
}

/// Reads a version number a caller asked for.
///
/// # Errors
///
/// When it is not a number this Store could have issued.
pub fn parse_number(raw: &str) -> Result<i64, BackendError> {
    raw.parse()
        .map_err(|_| BackendError::NoSuchVersion(raw.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const OTHER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn ring(active: &str, keys: &[(&str, &str)]) -> Keyring {
        Keyring::new(
            active,
            keys.iter()
                .map(|(id, k)| ((*id).to_owned(), (*k).to_owned())),
        )
        .expect("a valid keyring")
    }

    fn version(id: &str, state: VersionState) -> Version {
        Version {
            id: id.to_owned(),
            state,
        }
    }

    #[test]
    fn a_payload_round_trips() {
        let keyring = ring("v1", &[("v1", KEY)]);
        let sealed = OwnVersion::seal(&keyring, "local", "db-creds", 1, b"hunter2").unwrap();
        assert_eq!(sealed.open(&keyring).unwrap(), b"hunter2");
    }

    #[test]
    fn a_destroyed_version_has_nothing_to_reveal() {
        let keyring = ring("v1", &[("v1", KEY)]);
        let mut sealed = OwnVersion::seal(&keyring, "local", "db-creds", 1, b"hunter2").unwrap();
        sealed.state = VersionState::Destroyed;

        assert!(matches!(
            sealed.open(&keyring),
            Err(BackendError::NoSuchVersion(_))
        ));
    }

    #[test]
    fn a_version_moved_to_another_secret_will_not_open() {
        let keyring = ring("v1", &[("v1", KEY)]);
        let mut sealed = OwnVersion::seal(&keyring, "local", "db-creds", 1, b"hunter2").unwrap();
        sealed.secret = "api-key".to_owned();

        assert!(sealed.open(&keyring).is_err());
    }

    #[test]
    fn a_version_renumbered_will_not_open() {
        // The number is bound into the tag, so rows cannot be shuffled.
        let keyring = ring("v1", &[("v1", KEY)]);
        let mut sealed = OwnVersion::seal(&keyring, "local", "db-creds", 1, b"hunter2").unwrap();
        sealed.number = 2;

        assert!(sealed.open(&keyring).is_err());
    }

    #[test]
    fn a_version_sealed_under_a_retired_key_still_opens() {
        let old = ring("v1", &[("v1", KEY)]);
        let sealed = OwnVersion::seal(&old, "local", "db-creds", 1, b"hunter2").unwrap();
        assert_eq!(sealed.sealed.key_id, "v1");

        let rotated = ring("v2", &[("v1", KEY), ("v2", OTHER_KEY)]);
        assert_eq!(sealed.open(&rotated).unwrap(), b"hunter2");
    }

    #[test]
    fn the_next_number_follows_the_highest() {
        assert_eq!(next_number(&[]), 1);
        assert_eq!(next_number(&[version("1", VersionState::Enabled)]), 2);
        // Including versions that can no longer be read: reusing a number
        // would make two different payloads share an identity.
        assert_eq!(
            next_number(&[
                version("1", VersionState::Enabled),
                version("2", VersionState::Destroyed),
            ]),
            3
        );
    }

    #[test]
    fn the_latest_is_the_newest_readable_one() {
        let versions = [
            version("1", VersionState::Enabled),
            version("2", VersionState::Enabled),
            version("3", VersionState::Destroyed),
        ];
        assert_eq!(latest(&versions).map(|v| v.id.as_str()), Some("2"));
    }

    #[test]
    fn a_secret_with_no_readable_version_has_no_latest() {
        assert_eq!(latest(&[]), None);
        assert_eq!(latest(&[version("1", VersionState::Destroyed)]), None);
    }

    #[test]
    fn a_version_number_that_is_not_a_number_is_refused() {
        assert!(parse_number("latest").is_err());
        assert!(parse_number("1; DROP TABLE").is_err());
        assert_eq!(parse_number("7").unwrap(), 7);
    }
}
