use crate::domains::access::entity::{Level, Subject};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

/// Who is asking.
///
/// Resolved once at the edge and never re-derived: a browser session reads all
/// of this from the claim, and an API token names a handle and takes the
/// groups keyway remembered (ADR-0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    handle: String,
    groups: BTreeSet<String>,
    roles: BTreeSet<Role>,
    /// The public id of the API token this request arrived on, if it did. Kept
    /// so an audit row can name WHICH credential acted, not merely which
    /// account.
    via_token: Option<String>,
}

/// What a person may do irrespective of any one secret.
///
/// Roles do not cap a delegation and are not how sight of a secret is granted
/// — that is the delegation's own job (ADR-0002). There are only two, and the
/// list is deliberately short: everything about a particular secret is
/// answered by ownership or by a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Every secret in every Store, and delegation on secrets this caller does
    /// not own. The operational bypass.
    Admin,
    /// May bring new secrets into the inventory, owned by whoever made them.
    /// Independent of Admin: somebody who administers the platform need not be
    /// the person adding to it, and somebody adding to it need not administer.
    Create,
}

impl Role {
    /// The role name as a claim spells it, without the configured prefix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Create => "create",
        }
    }

    /// Reads a role out of a claim value that has already had the deployment's
    /// prefix stripped. A name nothing here can interpret is `None`, which is
    /// the only safe reading of a word this build does not know.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "admin" => Some(Role::Admin),
            "create" => Some(Role::Create),
            _ => None,
        }
    }
}

impl Actor {
    #[must_use]
    pub fn new(
        handle: impl Into<String>,
        groups: impl IntoIterator<Item = String>,
        roles: impl IntoIterator<Item = Role>,
    ) -> Self {
        Self {
            handle: handle.into(),
            groups: groups.into_iter().collect(),
            roles: roles.into_iter().collect(),
            via_token: None,
        }
    }

    /// The same actor, arriving on an API token.
    #[must_use]
    pub fn via_token(mut self, token_id: impl Into<String>) -> Self {
        self.via_token = Some(token_id.into());
        self
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn token_id(&self) -> Option<&str> {
        self.via_token.as_deref()
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.roles.contains(&Role::Admin)
    }

    #[must_use]
    pub fn may_create(&self) -> bool {
        self.roles.contains(&Role::Admin) || self.roles.contains(&Role::Create)
    }

    /// Whether a delegation addressed to `subject` is addressed to THIS caller.
    ///
    /// A group is matched by exact name. keyway parses no structure out of a
    /// group name (ADR-0003), so an issuer wanting a grant to a parent group
    /// to cover the teams inside it emits the ancestors in the claim — and
    /// then they are ordinary members of this set.
    #[must_use]
    pub fn is_addressed_by(&self, subject: &Subject) -> bool {
        match subject {
            Subject::User(handle) => handle == &self.handle,
            Subject::Group(name) => self.groups.contains(name),
        }
    }

    /// The groups this caller is in, for a console to show.
    #[must_use]
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().cloned().collect()
    }

    /// The roles this caller holds, by name.
    #[must_use]
    pub fn role_names(&self) -> Vec<String> {
        self.roles.iter().map(|r| r.as_str().to_owned()).collect()
    }

    /// Every string a delegation could name this caller by.
    #[must_use]
    pub fn subjects(&self) -> Vec<Subject> {
        let mut subjects = vec![Subject::User(self.handle.clone())];
        subjects.extend(self.groups.iter().cloned().map(Subject::Group));
        subjects
    }

    /// The highest level this caller holds anywhere.
    ///
    /// Never an answer about a particular secret — that is [`crate::domains::access`] —
    /// only what an account badge says. Two people with the same badge may
    /// hold nothing in common.
    #[must_use]
    pub fn ceiling(&self) -> Option<Level> {
        if self.is_admin() {
            Some(Level::Write)
        } else {
            None
        }
    }
}

/// What keyway remembers about a person between sign-ins.
///
/// The groups claim as it stood at their last sign-in, so an API token — which
/// carries no claim of its own — can act as its holder in full (ADR-0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberedUser {
    pub handle: String,
    pub groups: Vec<String>,
    pub email: String,
    pub name: String,
    pub last_login: DateTime<Utc>,
}
