//! The HTTP surface, against a real Postgres and a real router.
//!
//! Skipped unless `KEYWAY_TEST_DATABASE_URL` is set.
//!
//! The External Secrets tests are the ones to be careful changing: that shape
//! is a contract other people's clusters depend on, and breaking it breaks
//! reconcile loops rather than a screen.

mod support;

use keyway::domains::identity::entity::Role;
use serde_json::{Value, json};

macro_rules! app {
    ($handle:expr, $roles:expr, $groups:expr) => {{
        let Some(pool) = support::pool().await else {
            return;
        };
        support::app::start(pool, $handle, $roles, $groups).await
    }};
}

/// Creates a secret and returns its uuid.
async fn seed(app: &support::app::App, name: &str, value: &str) -> String {
    let created: Value = app
        .client
        .post(app.url("/api/secrets"))
        .json(&json!({ "store": "local", "name": name, "value": value }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("json");
    created["id"].as_str().expect("an id").to_owned()
}

#[tokio::test]
async fn a_secret_is_addressed_by_uuid_not_by_name() {
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db-creds", "hunter2").await;

    // The name is a label people read; every route speaks the uuid.
    let by_id = app
        .client
        .get(app.url(&format!("/api/secrets/{id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(by_id.status(), 200);

    let by_name = app
        .client
        .get(app.url("/api/secrets/db-creds"))
        .send()
        .await
        .unwrap();
    assert_eq!(by_name.status(), 400, "a name is not an address");
}

#[tokio::test]
async fn eso_reads_a_whole_kv_secret_as_flat_json() {
    // `dataFrom` with no `property`. The shape ESO expects.
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db", r#"{"db_password":"hunter2","api_key":"abc"}"#).await;

    let body = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let parsed: Value = serde_json::from_str(&body).expect("flat json");
    assert_eq!(parsed["db_password"], "hunter2");
    assert_eq!(parsed["api_key"], "abc");
}

#[tokio::test]
async fn eso_reads_one_property_as_a_raw_value() {
    // `remoteRef.property: db_password`. Raw, not JSON-quoted — a quoted value
    // would land in the Kubernetes Secret with the quotes in it.
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db", r#"{"db_password":"hunter2"}"#).await;

    let body = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value?key=db_password")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "hunter2", "no quotes, no whitespace, no newline");
}

#[tokio::test]
async fn eso_reads_a_text_secret_verbatim() {
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "token", "not-json-at-all").await;

    let body = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "not-json-at-all");
}

#[tokio::test]
async fn a_reveal_is_never_cached() {
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db", "hunter2").await;

    let response = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value")))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "no-store",
        "nothing on the way back should keep a value"
    );
}

#[tokio::test]
async fn a_secret_nobody_granted_is_not_found_rather_than_forbidden() {
    // A distinguishable answer would let anyone enumerate the inventory.
    let owner = app!("alice", &[Role::Create], &[]);
    let id = seed(&owner, "db-creds", "hunter2").await;

    let stranger = support::app::start(owner.pool.clone(), "mallory", &[], &[]).await;
    let response = stranger
        .client
        .get(stranger.url(&format!("/api/secrets/{id}")))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn a_listing_shows_only_what_the_caller_can_see() {
    let owner = app!("alice", &[Role::Create], &[]);
    seed(&owner, "db-creds", "hunter2").await;

    let stranger = support::app::start(owner.pool.clone(), "mallory", &[], &[]).await;
    let listed: Value = stranger
        .client
        .get(stranger.url("/api/secrets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(listed.as_array().unwrap().len(), 0);
    let mine: Value = owner
        .client
        .get(owner.url("/api/secrets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mine.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_group_grant_reaches_a_member() {
    let owner = app!("alice", &[Role::Create], &[]);
    let id = seed(&owner, "db-creds", r#"{"db_password":"hunter2"}"#).await;

    owner
        .client
        .post(owner.url(&format!("/api/secrets/{id}/grants")))
        .json(&json!({
            "subject_kind": "group",
            "subject": "SRE",
            "level": "read",
            "keys": ["db_password"]
        }))
        .send()
        .await
        .unwrap();

    // Bob is in SRE and holds no roles at all: the grant alone opens it.
    let bob = support::app::start(owner.pool.clone(), "bob", &[], &["SRE"]).await;
    let value = bob
        .client
        .get(bob.url(&format!("/api/secrets/{id}/value?key=db_password")))
        .send()
        .await
        .unwrap();
    assert_eq!(value.status(), 200);
    assert_eq!(value.text().await.unwrap(), "hunter2");
}

#[tokio::test]
async fn a_key_scoped_grant_opens_only_that_key() {
    let owner = app!("alice", &[Role::Create], &[]);
    let id = seed(
        &owner,
        "bot-creds",
        r#"{"db_password":"hunter2","api_key":"abc"}"#,
    )
    .await;

    owner
        .client
        .post(owner.url(&format!("/api/secrets/{id}/grants")))
        .json(&json!({
            "subject_kind": "group", "subject": "SRE",
            "level": "read", "keys": ["db_password"]
        }))
        .send()
        .await
        .unwrap();

    let bob = support::app::start(owner.pool.clone(), "bob", &[], &["SRE"]).await;
    let granted = bob
        .client
        .get(bob.url(&format!("/api/secrets/{id}/value?key=db_password")))
        .send()
        .await
        .unwrap();
    assert_eq!(granted.status(), 200);

    // What makes it safe to bundle a bot's credentials into one secret.
    let withheld = bob
        .client
        .get(bob.url(&format!("/api/secrets/{id}/value?key=api_key")))
        .send()
        .await
        .unwrap();
    assert_eq!(withheld.status(), 403);
}

#[tokio::test]
async fn a_read_grant_does_not_permit_a_new_version() {
    let owner = app!("alice", &[Role::Create], &[]);
    let id = seed(&owner, "db-creds", "hunter2").await;

    owner
        .client
        .post(owner.url(&format!("/api/secrets/{id}/grants")))
        .json(&json!({"subject_kind": "user", "subject": "bob", "level": "read"}))
        .send()
        .await
        .unwrap();

    let bob = support::app::start(owner.pool.clone(), "bob", &[], &[]).await;
    let patched = bob
        .client
        .post(bob.url(&format!("/api/secrets/{id}/versions")))
        .json(&json!({"value": "hunter3"}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), 403);
}

#[tokio::test]
async fn a_grantee_at_write_still_cannot_delete_or_re_delegate() {
    // Ownership, not level, carries the right to destroy or hand on.
    let owner = app!("alice", &[Role::Create], &[]);
    let id = seed(&owner, "db-creds", "hunter2").await;

    owner
        .client
        .post(owner.url(&format!("/api/secrets/{id}/grants")))
        .json(&json!({"subject_kind": "user", "subject": "bob", "level": "write"}))
        .send()
        .await
        .unwrap();

    let bob = support::app::start(owner.pool.clone(), "bob", &[], &[]).await;

    let pushed = bob
        .client
        .post(bob.url(&format!("/api/secrets/{id}/versions")))
        .json(&json!({"value": "hunter3"}))
        .send()
        .await
        .unwrap();
    assert_eq!(pushed.status(), 200, "write may push a version");

    let deleted = bob
        .client
        .delete(bob.url(&format!("/api/secrets/{id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 403, "write is not the power to destroy");

    let redelegated = bob
        .client
        .post(bob.url(&format!("/api/secrets/{id}/grants")))
        .json(&json!({"subject_kind": "user", "subject": "mallory", "level": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(redelegated.status(), 403, "a grantee cannot re-delegate");
}

#[tokio::test]
async fn a_token_acts_as_its_holder_and_is_named_in_the_audit_row() {
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db-creds", "hunter2").await;

    let minted: Value = app
        .client
        .post(app.url("/api/tokens"))
        .json(&json!({"name": "eso prod"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap();
    let token_id = minted["id"].as_str().unwrap();

    let value = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(value.text().await.unwrap(), "hunter2");

    let (recorded,): (Option<String>,) = sqlx::query_as(
        "SELECT via_token FROM audit WHERE action = 'reveal' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(recorded.as_deref(), Some(token_id));
}

#[tokio::test]
async fn a_revoked_token_stops_working() {
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db-creds", "hunter2").await;

    let minted: Value = app
        .client
        .post(app.url("/api/tokens"))
        .json(&json!({"name": "temporary"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap().to_owned();

    app.client
        .delete(app.url(&format!("/api/tokens/{}", minted["id"].as_str().unwrap())))
        .send()
        .await
        .unwrap();

    // Without a Directory this is the ONLY revocation there is (ADR-0004).
    let after = app
        .client
        .get(app.url(&format!("/api/secrets/{id}/value")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 401);
}

#[tokio::test]
async fn the_audit_feed_is_admin_only() {
    let app = app!("alice", &[Role::Create], &[]);
    seed(&app, "db-creds", "hunter2").await;

    let refused = app.client.get(app.url("/api/audit")).send().await.unwrap();
    assert_eq!(refused.status(), 403, "create is not admin");

    let admin = support::app::start(app.pool.clone(), "root", &[Role::Admin], &[]).await;
    let allowed = admin
        .client
        .get(admin.url("/api/audit"))
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
}

#[tokio::test]
async fn creating_a_secret_needs_the_create_role() {
    let app = app!("alice", &[], &[]);
    let refused = app
        .client
        .post(app.url("/api/secrets"))
        .json(&json!({"store": "local", "name": "db", "value": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
}

#[tokio::test]
async fn viewing_does_not_write_a_reveal() {
    // Browsing must never fill the audit log with reveals nobody performed.
    let app = app!("alice", &[Role::Create], &[]);
    let id = seed(&app, "db-creds", "hunter2").await;

    app.client
        .get(app.url(&format!("/api/secrets/{id}")))
        .send()
        .await
        .unwrap();

    let (reveals,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit WHERE action = 'reveal'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(reveals, 0);
}
