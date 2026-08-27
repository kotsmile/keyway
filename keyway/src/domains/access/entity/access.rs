//! How far a caller gets on one secret.
//!
//! This is the whole authorisation test, and it is deliberately small. Under
//! ADR-0002 a delegation carries its own level and nothing caps it, so there
//! is no ceiling to intersect and no role to consult: the answer is ownership,
//! or the grant addressed to this caller, or nothing.
//!
//! Keeping it in one function is the point. "Who can see this secret, and how
//! far" has to be answerable by reading one list, and that is only true if
//! every code path asks the same question the same way.

use super::{Delegation, Level, Ownership};
use crate::domains::identity::entity::Actor;
use chrono::{DateTime, Utc};

/// What a caller may do with one secret, and why.
///
/// The reason is carried because a refusal owes its reader a sentence, and
/// because the audit log records the basis on which a reveal was allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub level: Option<Level>,
    pub basis: Basis,
    /// Which keys of a key/value secret are open, or `None` for all of them.
    pub keys: Option<Vec<String>>,
}

/// Why a caller may do what they may.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// Nothing opens this secret for this caller.
    Nothing,
    /// They own it, so they run it outright whatever role they hold.
    Owner,
    /// The operational bypass.
    Admin,
    /// A grant, and who it was addressed to — a handle or a group name, which
    /// is what a person needs in order to know where their access came from.
    Delegated { subject: String },
}

impl Access {
    /// Nothing at all.
    #[must_use]
    pub fn none() -> Self {
        Self {
            level: None,
            basis: Basis::Nothing,
            keys: None,
        }
    }

    /// Whether this opens the secret at least as far as `wanted`.
    #[must_use]
    pub fn allows(&self, wanted: Level) -> bool {
        self.level.is_some_and(|held| held >= wanted)
    }

    /// Whether this opens `key` of a key/value secret at `wanted`.
    #[must_use]
    pub fn allows_key(&self, wanted: Level, key: &str) -> bool {
        self.allows(wanted)
            && self
                .keys
                .as_ref()
                .is_none_or(|keys| keys.iter().any(|k| k == key))
    }

    /// Whether the secret's existence should be disclosed at all.
    #[must_use]
    pub fn is_visible(&self) -> bool {
        self.level.is_some()
    }
}

/// How far `actor` gets on the secret that `ownership` and `grants` describe.
///
/// `grants` is every delegation written against that secret, whoever it is
/// addressed to — this function picks out the ones that name the caller. That
/// is deliberate: a caller-filtered query would put half the authorisation
/// rule in SQL, where the next person to write a query is free to get it
/// wrong.
#[must_use]
pub fn resolve(
    actor: &Actor,
    ownership: Option<&Ownership>,
    grants: &[Delegation],
    now: DateTime<Utc>,
) -> Access {
    // An owner runs their secret outright: change it, delegate it, revoke a
    // grant, transfer it. Checked before admin so the audit basis names the
    // narrower, truer reason.
    if ownership.is_some_and(|owned| owned.owner == actor.handle()) {
        return Access {
            level: Some(Level::Write),
            basis: Basis::Owner,
            keys: None,
        };
    }

    if actor.is_admin() {
        return Access {
            level: Some(Level::Write),
            basis: Basis::Admin,
            keys: None,
        };
    }

    // The best active grant addressed to this caller. Best rather than first:
    // a person may be named directly and through a group, and the answer is
    // the most that was granted, not whichever row the database returned
    // first.
    let mut best: Option<&Delegation> = None;
    for grant in grants {
        if !grant.is_active(now) || !actor.is_addressed_by(&grant.subject) {
            continue;
        }
        if best.is_none_or(|held| grant.level > held.level) {
            best = Some(grant);
        }
    }

    best.map_or_else(Access::none, |grant| Access {
        level: Some(grant.level),
        basis: Basis::Delegated {
            subject: grant.subject.id().to_owned(),
        },
        keys: grant.scoped_keys().map(<[String]>::to_vec),
    })
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
