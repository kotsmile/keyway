use super::{Level, Subject};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A grant over one secret, to one subject, at one level.
///
/// It is self-describing: what it says is what it opens, and no role caps it
/// (ADR-0002). The grantee still cannot re-delegate it or transfer it — those
/// belong to ownership, which is a different act with a different audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub id: Uuid,
    pub store: String,
    pub secret: String,
    pub subject: Subject,
    pub level: Level,
    /// Narrows the grant to some entries of a key/value secret; empty is the
    /// whole secret. This is what makes it safe to bundle a bot's credentials
    /// into one secret and still hand out exactly one of them.
    pub keys: Vec<String>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    /// `None` is indefinite, which is the common case.
    pub expires_at: Option<DateTime<Utc>>,
    /// Why it was granted: the sentence the next admin needs in order to
    /// decide whether it is still true.
    pub note: String,
}

impl Delegation {
    /// Whether this grant opens anything at `now`.
    ///
    /// An expired row is kept rather than deleted: "who used to be able to see
    /// this" is a question an incident asks, and a deleted row cannot answer
    /// it.
    #[must_use]
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }

    /// Whether this grant covers `key` of a key/value secret.
    ///
    /// An empty key list is the whole secret, so it covers everything —
    /// including keys that did not exist when the grant was written. That is
    /// the intended reading: the grant names a secret, not a snapshot of it.
    #[must_use]
    pub fn covers_key(&self, key: &str) -> bool {
        self.keys.is_empty() || self.keys.iter().any(|k| k == key)
    }

    /// The keys this grant opens, or `None` for the whole secret.
    #[must_use]
    pub fn scoped_keys(&self) -> Option<&[String]> {
        if self.keys.is_empty() {
            None
        } else {
            Some(&self.keys)
        }
    }
}

/// Who a secret belongs to.
///
/// Always a person: a group cannot own a secret, because an owner is who you
/// *ask* about one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    pub store: String,
    pub secret: String,
    pub owner: String,
    /// When they became the owner — set on create, reset by a transfer. So it
    /// reads as "has held this since", not "the secret was created then".
    pub since: DateTime<Utc>,
}
