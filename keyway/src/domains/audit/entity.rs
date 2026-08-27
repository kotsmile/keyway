//! What happened, and who did it.
//!
//! Reads are recorded alongside writes, which is unusual and intended: for a
//! secrets tool the interesting question is far more often "who looked at
//! this" than "who changed it".
//!
//! Append-only. There is no update and no delete in this module, and none
//! anywhere else either.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Create,
    Update,
    /// A value was read. The reason `reveal` exists as a word separate from
    /// "read".
    Reveal,
    Delete,
    Delegate,
    Revoke,
    /// Ownership changing hands. Its own action rather than a delegate with a
    /// flag, because it is the one entry that says who STOPPED being
    /// answerable for a secret.
    Transfer,
}

impl Action {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Update => "update",
            Action::Reveal => "reveal",
            Action::Delete => "delete",
            Action::Delegate => "delegate",
            Action::Revoke => "revoke",
            Action::Transfer => "transfer",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "create" => Action::Create,
            "update" => Action::Update,
            "reveal" => Action::Reveal,
            "delete" => Action::Delete,
            "delegate" => Action::Delegate,
            "revoke" => Action::Revoke,
            "transfer" => Action::Transfer,
            _ => return None,
        })
    }
}

/// One line of the log. It records WHAT was touched and by whom, never the
/// payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub actor: String,
    /// The public id of the API token that acted, absent for a browser
    /// session. What the id half of `kw-<id>-<secret>` exists for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_token: Option<String>,
    pub action: Action,
    pub store: String,
    pub secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Which key/value entries the action touched. Never the values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// The grantee, for a delegate or revoke — and the NEW owner, for a
    /// transfer.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// What to append. A builder rather than eight positional arguments, because
/// most entries set two of them and an argument list nobody can read is an
/// argument list somebody eventually passes in the wrong order.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    pub action: Action,
    pub store: &'a str,
    pub secret: &'a str,
    pub version: &'a str,
    pub keys: Vec<String>,
    pub subject: &'a str,
    pub note: &'a str,
}

impl<'a> Record<'a> {
    #[must_use]
    pub fn new(action: Action, store: &'a str, secret: &'a str) -> Self {
        Self {
            action,
            store,
            secret,
            version: "",
            keys: Vec::new(),
            subject: "",
            note: "",
        }
    }

    #[must_use]
    pub fn version(mut self, version: &'a str) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn keys(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.keys = keys.into_iter().collect();
        self
    }

    #[must_use]
    pub fn subject(mut self, subject: &'a str) -> Self {
        self.subject = subject;
        self
    }

    #[must_use]
    pub fn note(mut self, note: &'a str) -> Self {
        self.note = note;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_round_trips_through_its_word() {
        for action in [
            Action::Create,
            Action::Update,
            Action::Reveal,
            Action::Delete,
            Action::Delegate,
            Action::Revoke,
            Action::Transfer,
        ] {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
    }

    #[test]
    fn a_record_defaults_to_the_fields_most_entries_do_not_set() {
        let record = Record::new(Action::Reveal, "gcp-prod", "db-creds");
        assert!(record.version.is_empty());
        assert!(record.keys.is_empty());
        assert!(record.subject.is_empty());
    }
}
