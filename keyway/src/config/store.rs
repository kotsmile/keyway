use super::Selector;
use serde::Deserialize;
use serde_norway::Mapping;

/// One configured backing service.
///
/// A Store is configuration; the code behind it is a `SecretManager`, named by
/// `type`. Two Stores may name the same one — a production project and a
/// sandbox — and each carries its own scope, its own verbs and its own
/// credential.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct StoreConfig {
    /// The stable handle used in URLs and in the delegations table. Renaming
    /// one orphans its grants, so it is chosen once and left alone.
    pub id: String,
    /// Which `SecretManager` serves it.
    #[serde(rename = "type")]
    pub kind: String,
    /// What a person picks from the menu. Falls back to the id.
    #[serde(default)]
    pub title: String,
    /// What this deployment may do here.
    pub allow: Vec<Verb>,
    /// Which of the backend's secrets this Store exposes at all. Empty selects
    /// everything.
    #[serde(default)]
    pub select: Selector,
    /// Which of those are shown but refused for editing, because a reconciler
    /// owns them. Defaults to the External Secrets, Argo CD and Helm markers.
    #[serde(default = "Selector::reconciler_defaults")]
    pub protect: Selector,
    /// Everything else in the block: the keys this Store's `SecretManager` reads
    /// and no other. `project` for GCP, `folder` for Lockbox, `namespace` for
    /// Kubernetes. They are not in this schema because an adapter is the only
    /// thing that can validate them.
    #[serde(flatten)]
    pub settings: Mapping,
}

impl StoreConfig {
    /// The title, or the id when none was given.
    #[must_use]
    pub fn display_title(&self) -> &str {
        if self.title.is_empty() {
            &self.id
        } else {
            &self.title
        }
    }

    /// Whether one verb is permitted here.
    #[must_use]
    pub fn can(&self, verb: Verb) -> bool {
        self.allow.contains(&verb)
    }
}

/// What a deployment grants on one Store.
///
/// Four verbs rather than a `read_only` flag, because the interesting
/// configuration is neither end of that boolean: it is the shared production
/// project keyway may read and amend but must never create or destroy in.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    /// Everything that discloses: list, get, versions, access.
    Read,
    /// Changing a secret that exists: a new version, new labels.
    Edit,
    /// Bringing a new secret into existence.
    Create,
    /// Destroying one. Deliberately not folded into `create`: they look like a
    /// lifecycle pair, but only one of them can lose data, and letting people
    /// add secrets to a project is not thereby letting them remove the ones
    /// already there.
    Delete,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(yaml: &str) -> StoreConfig {
        serde_norway::from_str(yaml).expect("valid store")
    }

    #[test]
    fn adapter_keys_land_in_settings_rather_than_failing_the_parse() {
        let s = store("id: gcp-prod\ntype: gcp\nallow: [read]\nproject: acme\n");
        assert_eq!(
            s.settings.get("project").and_then(|v| v.as_str()),
            Some("acme")
        );
        assert!(
            s.settings.get("id").is_none(),
            "known keys are not settings"
        );
    }

    #[test]
    fn protect_defaults_to_the_reconciler_markers() {
        let s = store("id: k8s\ntype: k8s\nallow: [read, edit]\n");
        assert_eq!(s.protect, Selector::reconciler_defaults());
        assert!(
            s.select.is_empty(),
            "saying nothing about select exposes everything"
        );
    }

    #[test]
    fn protect_can_be_emptied_deliberately() {
        let s = store("id: k8s\ntype: k8s\nallow: [read]\nprotect: {}\n");
        assert!(s.protect.is_empty());
    }

    #[test]
    fn verbs_are_independent_of_one_another() {
        let s = store("id: prod\ntype: gcp\nallow: [read, edit]\n");
        assert!(s.can(Verb::Read));
        assert!(s.can(Verb::Edit));
        assert!(!s.can(Verb::Create), "editing is not creating");
        assert!(!s.can(Verb::Delete), "editing is not destroying");
    }

    #[test]
    fn a_title_falls_back_to_the_id() {
        let s = store("id: gcp-prod\ntype: gcp\nallow: [read]\n");
        assert_eq!(s.display_title(), "gcp-prod");
    }
}
