//! What the schema guarantees, against a real Postgres.
//!
//! Skipped unless `KEYWAY_TEST_DATABASE_URL` is set, so `cargo test` stays
//! runnable with no database. CI sets it against a service container.
//!
//! These assert the properties the migration's comments claim. Every one of
//! them is a rule the service would otherwise have to remember on every code
//! path, and a rule enforced in one place cannot be forgotten in another.

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use uuid::Uuid;

/// A migrated database of this test's own.
///
/// Each test gets a private schema rather than sharing `public`: these run in
/// parallel, and a shared schema means one test's fixtures are another's
/// mystery failure.
async fn pool() -> Option<PgPool> {
    let url = std::env::var("KEYWAY_TEST_DATABASE_URL").ok()?;
    let schema = format!("test_{}", Uuid::new_v4().simple());

    let admin = PgPool::connect(&url)
        .await
        .expect("connect to test database");
    // Safe by construction: `schema` is `test_` plus a generated uuid's hex,
    // so there is nothing in it a caller could have influenced.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .expect("create test schema");
    admin.close().await;

    let options = PgConnectOptions::from_str(&url)
        .expect("a valid connection url")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .connect_with(options)
        .await
        .expect("connect to the test schema");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    Some(pool)
}

macro_rules! db {
    () => {
        match pool().await {
            Some(pool) => pool,
            None => {
                eprintln!("skipped: KEYWAY_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

async fn delegate(
    pool: &PgPool,
    kind: &str,
    subject: &str,
    level: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO delegations (id, store, secret, subject_kind, subject_id, level, granted_by)
         VALUES ($1, 'gcp-prod', 'db-creds', $2, $3, $4, 'alice')",
    )
    .bind(Uuid::new_v4())
    .bind(kind)
    .bind(subject)
    .bind(level)
    .execute(pool)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn migrations_apply_to_an_empty_database() {
    let pool = db!();
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT tablename FROM pg_tables
         WHERE schemaname = current_schema() ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<_> = tables.into_iter().map(|(t,)| t).collect();
    for expected in ["audit", "delegations", "ownership", "tokens", "users"] {
        assert!(names.contains(&expected.to_owned()), "missing {expected}");
    }
}

#[tokio::test]
async fn a_team_and_a_person_sharing_a_name_are_separate_grants() {
    // ADR-0003. Under a generic OIDC issuer a groups claim may yield bare
    // names, so the kind cannot be read off the spelling.
    let pool = db!();
    delegate(&pool, "user", "sre", "read").await.unwrap();
    delegate(&pool, "group", "sre", "write").await.unwrap();

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM delegations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn one_subject_holds_at_most_one_grant_per_secret() {
    // Otherwise "what does this open" is a max() over rows rather than an
    // answer, and a grant list means nothing.
    let pool = db!();
    delegate(&pool, "user", "sre", "read").await.unwrap();

    let second = delegate(&pool, "user", "sre", "write").await;
    assert!(
        second.is_err(),
        "a second grant must be refused, not stacked"
    );
}

#[tokio::test]
async fn a_retired_level_word_is_refused() {
    let pool = db!();
    assert!(delegate(&pool, "user", "bob", "readonly").await.is_err());
    assert!(delegate(&pool, "user", "bob", "viewer").await.is_err());
}

#[tokio::test]
async fn a_subject_is_a_user_or_a_group_and_nothing_else() {
    // Tokens bind to a user rather than being a subject of their own, so
    // there is no third kind to accept.
    let pool = db!();
    assert!(delegate(&pool, "service", "eso", "read").await.is_err());
}

#[tokio::test]
async fn a_secret_has_at_most_one_owner() {
    // Two owners is a list to argue about rather than an answer to "who do I
    // ask about this".
    let pool = db!();
    sqlx::query(
        "INSERT INTO ownership (store, secret, owner) VALUES ('gcp-prod','db-creds','alice')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let second = sqlx::query(
        "INSERT INTO ownership (store, secret, owner) VALUES ('gcp-prod','db-creds','bob')",
    )
    .execute(&pool)
    .await;
    assert!(
        second.is_err(),
        "a transfer replaces an owner, never adds one"
    );
}

#[tokio::test]
async fn an_audit_action_nobody_defined_is_refused() {
    let pool = db!();
    let written = sqlx::query(
        "INSERT INTO audit (actor, action, store, secret) VALUES ('alice','peek','gcp-prod','db')",
    )
    .execute(&pool)
    .await;
    assert!(written.is_err());
}

#[tokio::test]
async fn an_audit_row_can_name_the_token_that_acted() {
    // What the public id half of `kw-<id>-<secret>` exists for: a reveal by a
    // bot names which credential did it, not merely which account.
    let pool = db!();
    sqlx::query(
        "INSERT INTO audit (actor, via_token, action, store, secret)
         VALUES ('alice', '7f3a9c2e', 'reveal', 'gcp-prod', 'db-creds')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let (token,): (Option<String>,) = sqlx::query_as("SELECT via_token FROM audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(token.as_deref(), Some("7f3a9c2e"));
}

#[tokio::test]
async fn a_browser_session_leaves_no_token_on_the_audit_row() {
    let pool = db!();
    sqlx::query(
        "INSERT INTO audit (actor, action, store, secret)
         VALUES ('alice', 'reveal', 'gcp-prod', 'db-creds')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let (token,): (Option<String>,) = sqlx::query_as("SELECT via_token FROM audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(token, None);
}

#[tokio::test]
async fn remembered_groups_survive_a_round_trip() {
    // The claim as it stood at the last sign-in (ADR-0004), so a token can act
    // as its holder in full.
    let pool = db!();
    sqlx::query("INSERT INTO users (handle, groups) VALUES ('alice', $1)")
        .bind(vec!["SRE".to_owned(), "platform".to_owned()])
        .execute(&pool)
        .await
        .unwrap();

    let (groups,): (Vec<String>,) = sqlx::query_as("SELECT groups FROM users WHERE handle='alice'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(groups, ["SRE", "platform"]);
}

#[tokio::test]
async fn a_token_expiry_is_optional() {
    // NULL never expires, deliberately: an expiry on the credential a
    // reconcile loop presents is an outage scheduled for a day nobody picked.
    let pool = db!();
    sqlx::query(
        "INSERT INTO tokens (id, hash, subject, name) VALUES ('7f3a9c2e', $1, 'alice', 'eso prod')",
    )
    .bind(vec![0_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let (expires,): (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as("SELECT expires_at FROM tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expires, None);
}
