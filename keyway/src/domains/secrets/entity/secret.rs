use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A secret's metadata as a backend reports it: labels, annotations, tags.
pub type Metadata = BTreeMap<String, String>;

/// One secret's metadata — never its payload.
///
/// Listing is the most common thing keyway does and it must not read a single
/// value to do it: a list that decrypts everything is an audit log full of
/// reveals nobody performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Secret {
    /// Which Store it lives in.
    pub store: String,
    /// The name the backend knows it by. Not what keyway addresses it by: the
    /// API speaks uuids, because a name is somebody else's contract — ESO
    /// manifests and existing tooling address these by name, and renaming them
    /// to uuids would break every one of those to buy keyway an id it can
    /// carry in a label instead.
    pub name: String,
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub labels: Metadata,
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub annotations: Metadata,
    /// The version an unqualified read resolves to. Empty for a secret that
    /// exists but has never been given a payload, which some backends allow
    /// and which reads as "not set" rather than as an error.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub latest_version: String,
}

impl Secret {
    /// Where this secret lives, as it reads in an error or a log line.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}/{}", self.store, self.name)
    }
}

/// One immutable revision as the backend records it.
///
/// Note what is NOT here: an author. No secret manager records who added a
/// version, and that gap is exactly what keyway's audit log fills.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Version {
    /// The backend's own identifier for it.
    pub id: String,
    pub state: VersionState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VersionState {
    Enabled,
    Disabled,
    /// The payload is gone for good, so nothing may offer to reveal it.
    Destroyed,
}

impl Version {
    /// Whether this version still has a payload to reveal.
    #[must_use]
    pub fn readable(&self) -> bool {
        self.state == VersionState::Enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_enabled_version_can_be_revealed() {
        let version = |state| Version {
            id: "7".to_owned(),
            state,
        };
        assert!(version(VersionState::Enabled).readable());
        assert!(!version(VersionState::Disabled).readable());
        assert!(!version(VersionState::Destroyed).readable());
    }

    #[test]
    fn a_reference_names_the_store_and_the_name() {
        let secret = Secret {
            store: "gcp-prod".to_owned(),
            name: "db-creds".to_owned(),
            labels: Metadata::new(),
            annotations: Metadata::new(),
            latest_version: String::new(),
        };
        assert_eq!(secret.reference(), "gcp-prod/db-creds");
    }
}
