//! What a Store enforces around whatever adapter it wraps.
//!
//! These are the tests that matter most in this module: every one of them is a
//! way a future adapter could quietly do the wrong thing if the fence were in
//! the adapter rather than here.

use super::{
    BackendError, Metadata, Registry, Secret, SecretManager, Store, StoreError, Version,
    VersionState,
};
use crate::config::StoreConfig;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// An adapter that records what it was actually asked to do.
///
/// It enforces nothing at all — deliberately, since the point of these tests
/// is that the Store refuses before the adapter is ever reached.
#[derive(Default)]
struct Spy {
    secrets: Vec<Secret>,
    calls: Mutex<Vec<String>>,
}

impl Spy {
    fn with(secrets: Vec<Secret>) -> Self {
        Self {
            secrets,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, call: &str) {
        self.calls.lock().unwrap().push(call.to_owned());
    }

    fn was_asked_to(&self, call: &str) -> bool {
        self.calls.lock().unwrap().iter().any(|c| c == call)
    }
}

/// So a Store can hold the adapter while a test still watches it.
#[async_trait]
impl SecretManager for Arc<Spy> {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        (**self).list().await
    }
    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        (**self).get(name).await
    }
    async fn versions(&self, name: &str) -> Result<Vec<Version>, BackendError> {
        (**self).versions(name).await
    }
    async fn access(&self, name: &str, version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        (**self).access(name, version).await
    }
    async fn set_labels(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        (**self).set_labels(name, labels).await
    }
    async fn create(&self, name: &str, labels: Metadata) -> Result<(), BackendError> {
        (**self).create(name, labels).await
    }
    async fn add_version(&self, name: &str, payload: &[u8]) -> Result<Version, BackendError> {
        (**self).add_version(name, payload).await
    }
    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        (**self).delete(name).await
    }
}

#[async_trait]
impl SecretManager for Spy {
    async fn list(&self) -> Result<Vec<Secret>, BackendError> {
        self.record("list");
        Ok(self.secrets.clone())
    }

    async fn get(&self, name: &str) -> Result<Secret, BackendError> {
        self.record("get");
        self.secrets
            .iter()
            .find(|s| s.name == name)
            .cloned()
            .ok_or(BackendError::NotFound)
    }

    async fn versions(&self, _name: &str) -> Result<Vec<Version>, BackendError> {
        self.record("versions");
        Ok(vec![Version {
            id: "1".to_owned(),
            state: VersionState::Enabled,
        }])
    }

    async fn access(&self, _name: &str, _version: Option<&str>) -> Result<Vec<u8>, BackendError> {
        self.record("access");
        Ok(b"payload".to_vec())
    }

    async fn set_labels(&self, _name: &str, _labels: Metadata) -> Result<(), BackendError> {
        self.record("set_labels");
        Ok(())
    }

    async fn create(&self, _name: &str, _labels: Metadata) -> Result<(), BackendError> {
        self.record("create");
        Ok(())
    }

    async fn add_version(&self, _name: &str, _payload: &[u8]) -> Result<Version, BackendError> {
        self.record("add_version");
        Ok(Version {
            id: "2".to_owned(),
            state: VersionState::Enabled,
        })
    }

    async fn delete(&self, _name: &str) -> Result<(), BackendError> {
        self.record("delete");
        Ok(())
    }
}

fn secret(name: &str, labels: &[(&str, &str)]) -> Secret {
    Secret {
        store: String::new(),
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        annotations: Metadata::new(),
        latest_version: "1".to_owned(),
    }
}

fn config(yaml: &str) -> StoreConfig {
    serde_norway::from_str(yaml).expect("valid store config")
}

/// Mounts a Store, keeping a handle on the spy so a test can ask what the
/// adapter was actually asked to do.
fn mounted_with_spy(yaml: &str, secrets: Vec<Secret>) -> (Store, Arc<Spy>) {
    let spy = Arc::new(Spy::with(secrets));
    (Store::new(config(yaml), Box::new(spy.clone())), spy)
}

fn mounted(yaml: &str, secrets: Vec<Secret>) -> Store {
    mounted_with_spy(yaml, secrets).0
}

const READ_ONLY: &str = "id: prod\ntype: spy\nallow: [read]\n";
const READ_EDIT: &str = "id: prod\ntype: spy\nallow: [read, edit]\n";

#[tokio::test]
async fn a_verb_the_deployment_withheld_never_reaches_the_adapter() {
    let (store, spy) = mounted_with_spy(READ_ONLY, vec![secret("db", &[])]);

    let error = store.delete("db").await.unwrap_err();
    assert!(matches!(error, StoreError::NotAllowed { .. }));

    // The whole point of the fence living here: an adapter that forgot to
    // check `allow` could not have destroyed anything, because it was never
    // asked to.
    assert!(
        !spy.was_asked_to("delete"),
        "the refusal must happen before the adapter, not inside it"
    );
}

#[tokio::test]
async fn editing_is_not_creating_and_not_destroying() {
    let store = mounted(READ_EDIT, vec![secret("db", &[])]);

    assert!(store.add_version("db", b"new").await.is_ok());
    assert!(matches!(
        store.create("other", Metadata::new()).await.unwrap_err(),
        StoreError::NotAllowed { .. }
    ));
    assert!(matches!(
        store.delete("db").await.unwrap_err(),
        StoreError::NotAllowed { .. }
    ));
}

#[tokio::test]
async fn select_narrows_the_listing() {
    let yaml = "id: prod\ntype: spy\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n";
    let store = mounted(
        yaml,
        vec![
            secret("mine", &[("keyway", "true")]),
            secret("someone-elses", &[]),
        ],
    );

    let listed = store.list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "mine");
}

#[tokio::test]
async fn a_secret_outside_select_is_not_found_rather_than_refused() {
    // A Store that does not expose something must not confirm it exists.
    let yaml = "id: prod\ntype: spy\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n";
    let store = mounted(yaml, vec![secret("someone-elses", &[])]);

    let error = store.get("someone-elses").await.unwrap_err();
    assert!(matches!(error, StoreError::Backend(BackendError::NotFound)));
}

#[tokio::test]
async fn a_reconciler_owned_secret_is_readable_but_not_editable() {
    let store = mounted(
        READ_EDIT,
        vec![secret(
            "db",
            &[("reconcile.external-secrets.io/managed", "true")],
        )],
    );

    // Visible: hiding it would be worse than refusing the edit.
    assert!(store.get("db").await.is_ok());
    assert!(store.access("db", None).await.is_ok());

    let error = store.add_version("db", b"new").await.unwrap_err();
    let StoreError::Protected { marker, .. } = error else {
        panic!("expected a protected refusal, got {error:?}");
    };
    // The refusal names the marker, so its reader knows which tool owns it.
    assert!(marker.contains("external-secrets"), "marker was {marker:?}");
}

#[tokio::test]
async fn protection_covers_labels_a_deployment_added_itself() {
    let yaml =
        "id: prod\ntype: spy\nallow: [read, edit]\nprotect:\n  labels:\n    owned-by: terraform\n";
    let store = mounted(yaml, vec![secret("db", &[("owned-by", "terraform")])]);

    assert!(matches!(
        store.add_version("db", b"x").await.unwrap_err(),
        StoreError::Protected { .. }
    ));
}

#[tokio::test]
async fn a_listing_is_stamped_with_the_store_it_came_from() {
    // An adapter has no reason to know its own Store id; the Store fills it in
    // so a cross-store listing can be keyed without every adapter cooperating.
    let store = mounted(READ_ONLY, vec![secret("db", &[])]);
    assert_eq!(store.list().await.unwrap()[0].store, "prod");
    assert_eq!(store.get("db").await.unwrap().store, "prod");
}

#[test]
fn a_registry_keeps_declaration_order() {
    let stores = ["b", "a", "c"]
        .map(|id| mounted(&format!("id: {id}\ntype: spy\nallow: [read]\n"), Vec::new()));
    let registry = Registry::new(stores).unwrap();

    let ids: Vec<_> = registry.all().iter().map(|s| s.id().to_owned()).collect();
    assert_eq!(ids, ["b", "a", "c"], "the config decides what comes first");
}

#[test]
fn a_registry_refuses_two_stores_on_one_id() {
    let stores = ["prod", "prod"]
        .map(|id| mounted(&format!("id: {id}\ntype: spy\nallow: [read]\n"), Vec::new()));
    assert!(Registry::new(stores).is_err());
}

#[test]
fn an_unknown_store_id_resolves_to_nothing() {
    let registry = Registry::new([mounted(READ_ONLY, Vec::new())]).unwrap();
    assert!(registry.get("prod").is_some());
    assert!(registry.get("does-not-exist").is_none());
}
