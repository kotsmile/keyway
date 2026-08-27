//! The database keyway owns.
//!
//! What lives here is what a secret manager cannot answer: who owns a secret,
//! who may see it, and who looked. Payloads do not, except in keyway's own
//! Store — see the keyway `SecretManager` implementation, the one backend where
//! keyway holds a value at all.

use crate::config::Postgres;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connecting to postgres at {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: sqlx::Error,
    },
    #[error("the postgres address {addr:?} is not host:port")]
    BadAddress { addr: String },
    #[error("applying migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Opens the pool.
///
/// # Errors
///
/// When the address is not `host:port`, or the database refuses the
/// connection.
pub async fn connect(config: &Postgres) -> Result<PgPool, Error> {
    let (host, port) = config
        .addr
        .rsplit_once(':')
        .ok_or_else(|| Error::BadAddress {
            addr: config.addr.clone(),
        })?;
    let port: u16 = port.parse().map_err(|_| Error::BadAddress {
        addr: config.addr.clone(),
    })?;

    let options = PgConnectOptions::new()
        .host(host)
        .port(port)
        .database(&config.name)
        .username(&config.user)
        .password(&config.password)
        .ssl_mode(ssl_mode(&config.sslmode)?)
        // A statement carrying a credential must not land in a log at INFO.
        .disable_statement_logging();

    PgPoolOptions::new()
        .max_connections(config.max_conn)
        .connect_with(options)
        .await
        .map_err(|source| Error::Connect {
            addr: config.addr.clone(),
            source,
        })
}

fn ssl_mode(name: &str) -> Result<sqlx::postgres::PgSslMode, Error> {
    sqlx::postgres::PgSslMode::from_str(name).map_err(|_| Error::BadAddress {
        addr: format!("sslmode {name:?}"),
    })
}

/// Brings the schema up to date.
///
/// Run as its own command rather than on every boot: a rolling deploy with
/// three replicas racing to migrate is a deploy that fails in a way nobody can
/// reproduce.
///
/// # Errors
///
/// When a migration fails, or the recorded history does not match what ships.
pub async fn migrate(pool: &PgPool) -> Result<(), Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
