use std::fmt;

/// Who a delegation is addressed to.
///
/// The kind is carried in the type, never inferred from how the name is
/// spelled. locker told a group from a person by a leading `/`, which held
/// only because Keycloak group paths always start with one; under a generic
/// OIDC issuer a claim may yield bare names, and a team called `sre` would
/// then be indistinguishable from a person called `sre` (ADR-0003).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    /// A person, by the handle every service keys and logs on.
    User(String),
    /// A group, named exactly as the issuer's claim spells it. keyway parses
    /// no structure out of it: an issuer wanting a grant to a parent group to
    /// cover the teams inside it puts the ancestors in the claim.
    Group(String),
}

impl Subject {
    /// The word the `subject_kind` column stores.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Subject::User(_) => "user",
            Subject::Group(_) => "group",
        }
    }

    /// The name, without its kind.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Subject::User(id) | Subject::Group(id) => id,
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind(), self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_team_and_a_person_sharing_a_name_are_different_subjects() {
        // The scenario ADR-0003 exists for: an Okta claim of ["SRE"] beside a
        // person whose handle is "sre".
        assert_ne!(
            Subject::User("sre".to_owned()),
            Subject::Group("sre".to_owned())
        );
    }

    #[test]
    fn kind_and_id_are_reported_separately() {
        let group = Subject::Group("Engineering".to_owned());
        assert_eq!(group.kind(), "group");
        assert_eq!(group.id(), "Engineering");
    }

    #[test]
    fn a_slash_prefixed_name_is_not_thereby_a_group() {
        // Nothing reads the shape of a name any more, so a path-shaped handle
        // stays a user.
        let user = Subject::User("/sre".to_owned());
        assert_eq!(user.kind(), "user");
    }
}
