//! keyway's own Store, against a real Postgres.
//!
//! Skipped unless `KEYWAY_TEST_DATABASE_URL` is set. This is the one backend
//! where keyway holds a payload, so what these assert is that a value written
//! here comes back, that nothing written here is readable from the table
//! itself, and that rotating a key does not strand what came before it.

mod support;

use keyway::domain::{Metadata, VersionState};
use keyway::store::keyway::{Keyring, OwnStore};
use keyway::store::{BackendError, SecretManager};
use sqlx::PgPool;

/// 32 bytes of base64, distinct so a test can tell which one opened a payload.
const KEY_V1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const KEY_V2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

fn keyring(active: &str, keys: &[(&str, &str)]) -> Keyring {
    Keyring::new(
        active,
        keys.iter()
            .map(|(id, k)| ((*id).to_owned(), (*k).to_owned())),
    )
    .expect("a valid keyring")
}

fn store(pool: &PgPool, active: &str, keys: &[(&str, &str)]) -> OwnStore {
    OwnStore::new("local", pool.clone(), keyring(active, keys))
}

async fn with_secret(store: &OwnStore, name: &str, payload: &[u8]) {
    store.create(name, Metadata::new()).await.expect("create");
    store.add_version(name, payload).await.expect("add version");
}

#[tokio::test]
async fn a_value_written_comes_back() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    with_secret(&store, "db-creds", b"hunter2").await;

    assert_eq!(store.access("db-creds", None).await.unwrap(), b"hunter2");
}

#[tokio::test]
async fn the_payload_is_not_readable_from_the_table() {
    // The property the whole module exists for. Anyone with SELECT on the
    // database — a backup, a replica, a support query — sees ciphertext.
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    with_secret(&store, "db-creds", b"hunter2").await;

    let (ciphertext,): (Vec<u8>,) = sqlx::query_as("SELECT ciphertext FROM own_versions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !ciphertext.windows(7).any(|w| w == b"hunter2"),
        "the plaintext must not appear in the row"
    );
}

#[tokio::test]
async fn versions_accumulate_and_the_latest_wins() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    with_secret(&store, "db-creds", b"first").await;
    store.add_version("db-creds", b"second").await.unwrap();

    assert_eq!(store.access("db-creds", None).await.unwrap(), b"second");
    assert_eq!(store.access("db-creds", Some("1")).await.unwrap(), b"first");

    let versions = store.versions("db-creds").await.unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].id, "2", "newest first");
    assert_eq!(versions[0].state, VersionState::Enabled);
}

#[tokio::test]
async fn a_secret_reports_its_latest_version() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    store.create("db-creds", Metadata::new()).await.unwrap();
    let empty = store.get("db-creds").await.unwrap();
    assert_eq!(
        empty.latest_version, "",
        "a secret with no payload reads as not set, not as an error"
    );

    store.add_version("db-creds", b"hunter2").await.unwrap();
    assert_eq!(store.get("db-creds").await.unwrap().latest_version, "1");
}

#[tokio::test]
async fn a_version_sealed_under_a_retired_key_still_opens() {
    // The reason key_id is recorded per version. An operator who rotates must
    // not lose everything written before the rotation.
    let Some(pool) = support::pool().await else {
        return;
    };

    let before = store(&pool, "v1", &[("v1", KEY_V1)]);
    with_secret(&before, "db-creds", b"old-value").await;

    let after = store(&pool, "v2", &[("v1", KEY_V1), ("v2", KEY_V2)]);
    after.add_version("db-creds", b"new-value").await.unwrap();

    assert_eq!(
        after.access("db-creds", Some("1")).await.unwrap(),
        b"old-value"
    );
    assert_eq!(after.access("db-creds", None).await.unwrap(), b"new-value");

    let (key_ids,): (Vec<String>,) =
        sqlx::query_as("SELECT array_agg(key_id ORDER BY version) FROM own_versions")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(key_ids, ["v1", "v2"]);
}

#[tokio::test]
async fn keys_in_use_says_when_a_rotation_is_finished() {
    // What an operator has to ask before dropping a key from the config.
    let Some(pool) = support::pool().await else {
        return;
    };

    let before = store(&pool, "v1", &[("v1", KEY_V1)]);
    with_secret(&before, "db-creds", b"old").await;

    // Rotating the active key changes nothing on its own: what is already
    // sealed stays sealed under the old one.
    let after = store(&pool, "v2", &[("v1", KEY_V1), ("v2", KEY_V2)]);
    assert_eq!(after.keys_in_use().await.unwrap(), ["v1"]);

    // Only writing re-seals, and now both keys are needed.
    after.add_version("db-creds", b"new").await.unwrap();
    assert_eq!(after.keys_in_use().await.unwrap(), ["v1", "v2"]);

    // v1 is safe to drop only once nothing is sealed under it.
    sqlx::query("DELETE FROM own_versions WHERE key_id = 'v1'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(after.keys_in_use().await.unwrap(), ["v2"]);
}

#[tokio::test]
async fn dropping_a_key_still_in_use_fails_loudly() {
    let Some(pool) = support::pool().await else {
        return;
    };

    let before = store(&pool, "v1", &[("v1", KEY_V1)]);
    with_secret(&before, "db-creds", b"old").await;

    // v1 gone from the config while a version still needs it.
    let careless = store(&pool, "v2", &[("v2", KEY_V2)]);
    let error = careless.access("db-creds", Some("1")).await.unwrap_err();
    assert!(
        matches!(error, BackendError::Backend { .. }),
        "an unopenable payload must be an error, never empty bytes"
    );
}

#[tokio::test]
async fn two_stores_of_the_same_type_do_not_see_each_other() {
    // A deployment may declare a sandbox beside a real one.
    let Some(pool) = support::pool().await else {
        return;
    };
    let real = OwnStore::new("local", pool.clone(), keyring("v1", &[("v1", KEY_V1)]));
    let sandbox = OwnStore::new("sandbox", pool.clone(), keyring("v1", &[("v1", KEY_V1)]));

    with_secret(&real, "db-creds", b"hunter2").await;

    assert_eq!(real.list().await.unwrap().len(), 1);
    assert!(sandbox.list().await.unwrap().is_empty());
    assert!(matches!(
        sandbox.get("db-creds").await.unwrap_err(),
        BackendError::NotFound
    ));
}

#[tokio::test]
async fn labels_round_trip_and_can_be_replaced() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    let mut labels = Metadata::new();
    labels.insert("team".to_owned(), "infra".to_owned());
    store.create("db-creds", labels.clone()).await.unwrap();
    assert_eq!(store.get("db-creds").await.unwrap().labels, labels);

    let mut replaced = Metadata::new();
    replaced.insert("env".to_owned(), "prod".to_owned());
    store
        .set_labels("db-creds", replaced.clone())
        .await
        .unwrap();

    let after = store.get("db-creds").await.unwrap();
    assert_eq!(after.labels, replaced, "replace rather than merge");
}

#[tokio::test]
async fn deleting_a_secret_takes_its_versions_with_it() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    with_secret(&store, "db-creds", b"hunter2").await;
    store.delete("db-creds").await.unwrap();

    let (versions,): (i64,) = sqlx::query_as("SELECT count(*) FROM own_versions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        versions, 0,
        "an orphaned ciphertext is a secret nobody owns"
    );
}

#[tokio::test]
async fn acting_on_a_secret_that_does_not_exist_is_not_found() {
    let Some(pool) = support::pool().await else {
        return;
    };
    let store = store(&pool, "v1", &[("v1", KEY_V1)]);

    assert!(matches!(
        store.get("missing").await.unwrap_err(),
        BackendError::NotFound
    ));
    assert!(matches!(
        store.access("missing", None).await.unwrap_err(),
        BackendError::NotFound
    ));
    assert!(matches!(
        store.add_version("missing", b"x").await.unwrap_err(),
        BackendError::NotFound
    ));
    assert!(matches!(
        store.delete("missing").await.unwrap_err(),
        BackendError::NotFound
    ));
}
