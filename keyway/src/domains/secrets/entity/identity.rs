//! How a secret is addressed.
//!
//! Every route, every API call and every link is a uuid; the name is a label
//! people read. That is not keyway's preference so much as a consequence: the
//! name is somebody else's contract — External Secrets manifests and whatever
//! tooling already exists address these by name — so renaming secrets to uuids
//! would break every one of those to buy keyway an id it can carry in a label
//! instead.

use super::{Metadata, Secret};
use uuid::Uuid;

/// The backend label keyway keeps a secret's uuid in.
///
/// A label rather than the name, and one that satisfies the strictest grammar
/// among the backends (lowercase letters, digits, `-`, `_`, at most 63
/// characters). A uuid in canonical form is 36 lowercase hex characters and
/// dashes, so nothing has to be encoded.
pub const LABEL: &str = "keyway-id";

/// Seeds the derived ids below. A fixed random uuid, never changed: changing
/// it renames every unlabelled secret in one release.
const NAMESPACE: Uuid = Uuid::from_u128(0x9f2c_4e8a_7b31_4d6f_a05e_1c83_7d94_2b60);

/// The uuid a secret is addressed by.
///
/// The label is the answer whenever the backend carries one. When it does not
/// — every secret that predates keyway, and everything another tool created —
/// the id is DERIVED from (store, name) rather than minted at random, and that
/// is the whole reason this can ship without a backfill: an inventory of a
/// hundred untouched secrets is addressable from the first request.
///
/// Derivation is v5, so it is stable across processes, restarts and replicas —
/// three keyway pods answer the same uuid for the same secret without
/// coordinating.
#[must_use]
pub fn id_of(store: &str, name: &str, labels: &Metadata) -> Uuid {
    if let Some(labelled) = labels.get(LABEL).and_then(|v| Uuid::parse_str(v).ok()) {
        return labelled;
    }
    derive(store, name)
}

/// The id a secret takes when the backend carries no label.
#[must_use]
pub fn derive(store: &str, name: &str) -> Uuid {
    Uuid::new_v5(&NAMESPACE, format!("{store}/{name}").as_bytes())
}

/// The id this secret answers to.
#[must_use]
pub fn id_for(secret: &Secret) -> Uuid {
    id_of(&secret.store, &secret.name, &secret.labels)
}

/// Whether this secret already carries its id, or is still being addressed by
/// a derived one.
///
/// keyway writes the label the first time somebody opens a secret, purely so
/// the id stops depending on the name.
#[must_use]
pub fn is_labelled(secret: &Secret) -> bool {
    secret
        .labels
        .get(LABEL)
        .is_some_and(|v| Uuid::parse_str(v).is_ok())
}

/// The labels a secret should carry once adopted, or `None` if it already
/// does.
#[must_use]
pub fn adoption_labels(secret: &Secret) -> Option<Metadata> {
    if is_labelled(secret) {
        return None;
    }
    let mut labels = secret.labels.clone();
    labels.insert(LABEL.to_owned(), id_for(secret).to_string());
    Some(labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(store: &str, name: &str, labels: &[(&str, &str)]) -> Secret {
        Secret {
            store: store.to_owned(),
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            annotations: Metadata::new(),
            latest_version: String::new(),
        }
    }

    #[test]
    fn a_label_is_the_answer_when_the_backend_carries_one() {
        let known = Uuid::parse_str("7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f").unwrap();
        let s = secret("gcp-prod", "db-creds", &[(LABEL, &known.to_string())]);
        assert_eq!(id_for(&s), known);
    }

    #[test]
    fn an_unlabelled_secret_is_addressable_from_the_first_request() {
        // The reason this ships without a backfill.
        let s = secret("gcp-prod", "db-creds", &[]);
        assert_eq!(id_for(&s), derive("gcp-prod", "db-creds"));
    }

    #[test]
    fn derivation_is_stable_across_processes() {
        assert_eq!(
            derive("gcp-prod", "db-creds"),
            derive("gcp-prod", "db-creds"),
            "three replicas must answer the same uuid without coordinating"
        );
    }

    #[test]
    fn the_same_name_in_two_stores_is_two_secrets() {
        assert_ne!(
            derive("gcp-prod", "db-creds"),
            derive("aws-prod", "db-creds")
        );
    }

    #[test]
    fn a_malformed_label_falls_back_rather_than_failing() {
        // Somebody else's tooling may have written the key. Refusing to
        // address the secret at all would be worse than deriving one.
        let s = secret("gcp-prod", "db-creds", &[(LABEL, "not-a-uuid")]);
        assert_eq!(id_for(&s), derive("gcp-prod", "db-creds"));
        assert!(!is_labelled(&s));
    }

    #[test]
    fn adoption_writes_the_derived_id_and_keeps_the_rest() {
        let s = secret("gcp-prod", "db-creds", &[("team", "infra")]);
        let labels = adoption_labels(&s).expect("needs adopting");

        assert_eq!(
            labels.get(LABEL).unwrap(),
            &derive("gcp-prod", "db-creds").to_string()
        );
        assert_eq!(labels.get("team").unwrap(), "infra");
    }

    #[test]
    fn an_adopted_secret_is_not_adopted_twice() {
        let known = derive("gcp-prod", "db-creds").to_string();
        let s = secret("gcp-prod", "db-creds", &[(LABEL, &known)]);
        assert!(adoption_labels(&s).is_none());
    }

    #[test]
    fn a_labelled_secret_keeps_its_id_when_renamed() {
        // The whole point of the label: an id that stops depending on the name.
        let known = Uuid::parse_str("7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f").unwrap();
        let before = secret("gcp-prod", "old-name", &[(LABEL, &known.to_string())]);
        let after = secret("gcp-prod", "new-name", &[(LABEL, &known.to_string())]);

        assert_eq!(id_for(&before), id_for(&after));
    }
}
