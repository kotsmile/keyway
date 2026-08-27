use crate::domain::Metadata;
use serde::Deserialize;
use std::collections::BTreeMap;

/// A set of labels, annotations or tags to match a secret's metadata against.
///
/// One type serves both `select` and `protect`, but they ask different
/// questions of it, so it has two methods rather than one. `select` is a
/// filter — every entry must match, as a Kubernetes label selector does.
/// `protect` is a set of markers — any one matching is enough, because a
/// secret owned by External Secrets and a secret owned by Helm are both
/// somebody else's to edit.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// AWS spells labels `tags`. The generic `select` is mapped per backend,
    /// and this is where that mapping is spelled for the one that differs.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

/// The value that matches a key whatever it holds, for a marker whose value is
/// an id nobody can predict (`argocd.argoproj.io/tracking-id`).
const ANY: &str = "*";

impl Selector {
    /// Whether this selector asks for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty() && self.annotations.is_empty() && self.tags.is_empty()
    }

    /// Whether `metadata` satisfies EVERY entry — the `select` question.
    ///
    /// An empty selector selects everything, which is what a Store that has
    /// said nothing about scoping means.
    #[must_use]
    pub fn matches_all(&self, labels: &Metadata, annotations: &Metadata) -> bool {
        self.entries()
            .all(|(kind, key, want)| matches_one(kind, key, want, labels, annotations))
    }

    /// Whether `metadata` satisfies ANY entry — the `protect` question.
    ///
    /// An empty selector protects nothing, so a Store with no `protect` block
    /// behaves as though the concept did not exist.
    #[must_use]
    pub fn matches_any(&self, labels: &Metadata, annotations: &Metadata) -> bool {
        self.entries()
            .any(|(kind, key, want)| matches_one(kind, key, want, labels, annotations))
    }

    /// The first entry `metadata` satisfies, as `key=value` — what a refusal
    /// names so its reader knows which tool to go and look at.
    #[must_use]
    pub fn first_match(&self, labels: &Metadata, annotations: &Metadata) -> Option<String> {
        self.entries()
            .find(|(kind, key, want)| matches_one(*kind, key, want, labels, annotations))
            .map(|(_, key, want)| {
                if want == ANY {
                    key.to_owned()
                } else {
                    format!("{key}={want}")
                }
            })
    }

    fn entries(&self) -> impl Iterator<Item = (Kind, &str, &str)> {
        let labels = self
            .labels
            .iter()
            .chain(self.tags.iter())
            .map(|(k, v)| (Kind::Label, k.as_str(), v.as_str()));
        let annotations = self
            .annotations
            .iter()
            .map(|(k, v)| (Kind::Annotation, k.as_str(), v.as_str()));
        labels.chain(annotations)
    }

    /// The markers keyway refuses to edit unless a deployment says otherwise:
    /// External Secrets, Argo CD and Helm. They are defaults rather than
    /// hard-coded knowledge, so a site using different tooling overrides them.
    #[must_use]
    pub fn reconciler_defaults() -> Self {
        Self {
            labels: BTreeMap::from([
                (
                    "reconcile.external-secrets.io/managed".to_owned(),
                    "true".to_owned(),
                ),
                ("app.kubernetes.io/managed-by".to_owned(), "Helm".to_owned()),
            ]),
            annotations: BTreeMap::from([
                ("argocd.argoproj.io/tracking-id".to_owned(), ANY.to_owned()),
                ("meta.helm.sh/release-name".to_owned(), ANY.to_owned()),
            ]),
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Label,
    Annotation,
}

fn matches_one(
    kind: Kind,
    key: &str,
    want: &str,
    labels: &Metadata,
    annotations: &Metadata,
) -> bool {
    let source = match kind {
        Kind::Label => labels,
        Kind::Annotation => annotations,
    };
    match source.get(key) {
        Some(_) if want == ANY => true,
        Some(have) => have == want,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> Metadata {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn selector(yaml: &str) -> Selector {
        serde_norway::from_str(yaml).expect("valid selector")
    }

    #[test]
    fn an_empty_selector_selects_everything() {
        let all = Selector::default();
        assert!(all.matches_all(&meta(&[]), &meta(&[])));
        assert!(all.is_empty());
    }

    #[test]
    fn an_empty_selector_protects_nothing() {
        assert!(!Selector::default().matches_any(&meta(&[("any", "thing")]), &meta(&[])));
    }

    #[test]
    fn select_requires_every_entry() {
        let want = selector("labels:\n  team: infra\n  env: prod\n");
        assert!(want.matches_all(&meta(&[("team", "infra"), ("env", "prod")]), &meta(&[])));
        assert!(
            !want.matches_all(&meta(&[("team", "infra")]), &meta(&[])),
            "a partial match must not select"
        );
    }

    #[test]
    fn protect_needs_only_one_marker() {
        let markers = Selector::reconciler_defaults();
        let eso = meta(&[("reconcile.external-secrets.io/managed", "true")]);
        assert!(markers.matches_any(&eso, &meta(&[])));
    }

    #[test]
    fn a_wildcard_matches_a_value_nobody_can_predict() {
        let markers = Selector::reconciler_defaults();
        let tracked = meta(&[("argocd.argoproj.io/tracking-id", "payments:apps/Deployment")]);
        assert!(markers.matches_any(&meta(&[]), &tracked));
    }

    #[test]
    fn a_wildcard_still_needs_the_key_present() {
        let markers = Selector::reconciler_defaults();
        assert!(!markers.matches_any(&meta(&[]), &meta(&[("other", "value")])));
    }

    #[test]
    fn tags_are_matched_as_labels_for_the_backend_that_spells_them_so() {
        let want = selector("tags:\n  keyway: \"true\"\n");
        assert!(want.matches_all(&meta(&[("keyway", "true")]), &meta(&[])));
    }

    #[test]
    fn a_label_and_an_annotation_are_not_interchangeable() {
        let want = selector("labels:\n  team: infra\n");
        assert!(
            !want.matches_all(&meta(&[]), &meta(&[("team", "infra")])),
            "an annotation must not satisfy a label selector"
        );
    }
}
