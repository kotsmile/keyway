#![allow(dead_code)] // shared across test binaries; each uses part of it
//! A migrated database per test.
//!
//! Each test gets a private schema rather than sharing `public`: these run in
//! parallel, and a shared schema means one test's fixtures are another's
//! mystery failure.

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use uuid::Uuid;

pub async fn pool() -> Option<PgPool> {
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

pub mod app;
