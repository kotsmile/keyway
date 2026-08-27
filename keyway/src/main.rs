//! The keyway backend.

use clap::{Parser, Subcommand};
use eyre::Context as _;
use keyway::config::{Config, StoreConfig};
use keyway::container;
use keyway::domains::access::AccessService;
use keyway::domains::access::infra::PostgresAccessRepo;
use keyway::domains::audit::AuditService;
use keyway::domains::audit::infra::PostgresAuditRepo;
use keyway::domains::identity::IdentityService;
use keyway::domains::identity::entity::Role;
use keyway::domains::identity::infra::{KeycloakDirectory, Oidc, PostgresIdentityRepo};
use keyway::domains::secrets::OwnStoreService;
use keyway::domains::secrets::entity::{Keyring, Registry, SecretManager, Store};
use keyway::domains::secrets::infra::{GcpSecretManager, PostgresOwnStoreRepo};
use keyway::domains::tokens::TokenService;
use keyway::domains::tokens::infra::PostgresTokenRepo;
use keyway::infra::{postgres, telemetry};
use keyway::transport::auth_middleware::{AuthState, DevActor};
use keyway::{AppState, router};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "keyway",
    about = "A secrets console over the secret managers you already run"
)]
struct Cli {
    /// The single file this deployment is configured by.
    #[arg(long, short, default_value = "config.yml", global = true)]
    config: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP service.
    Serve,
    /// Bring the schema up to date.
    ///
    /// Its own command rather than something `serve` does: three replicas
    /// racing to migrate during a rolling deploy fail in a way nobody can
    /// reproduce.
    Migrate,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let config = keyway::config::load(&cli.config)?;

    let telemetry = telemetry::init(
        &config.telemetry.service_name,
        Some(config.telemetry.otlp_endpoint.as_str()).filter(|e| !e.is_empty()),
    )?;

    let pool = postgres::connect(&config.postgres).await?;

    match cli.command {
        Command::Migrate => {
            postgres::migrate(&pool).await?;
            tracing::info!("schema is up to date");
        }
        Command::Serve => serve(config, pool, &telemetry).await?,
    }

    telemetry.shutdown();
    Ok(())
}

async fn serve(
    config: Config,
    pool: sqlx::PgPool,
    telemetry: &telemetry::Telemetry,
) -> eyre::Result<()> {
    let access: container::Access = Arc::new(AccessService::new(Arc::new(
        PostgresAccessRepo::new(pool.clone()),
    )));
    let audit: container::Audit = Arc::new(AuditService::new(Arc::new(PostgresAuditRepo::new(
        pool.clone(),
    ))));
    let tokens: container::Tokens = Arc::new(TokenService::new(Arc::new(PostgresTokenRepo::new(
        pool.clone(),
    ))));
    // Without a Directory, a token's groups are what keyway remembered at its
    // holder's last sign-in, and deleting a token is the only revocation.
    let directory: Option<Arc<dyn keyway::domains::identity::Directory>> =
        match config.oidc.directory.as_str() {
            "" => None,
            "keycloak" => Some(Arc::new(KeycloakDirectory::new(
                &config.oidc.issuer,
                &config.oidc.client_id,
                &config.oidc.client_secret,
            )?)),
            other => {
                return Err(eyre::eyre!(
                    "oidc.directory names an unknown kind {other:?}; this build has: keycloak"
                ));
            }
        };
    if directory.is_some() {
        tracing::info!("directory configured; token holders are checked live");
    }
    let identity: container::Identity = Arc::new(IdentityService::new(
        Arc::new(PostgresIdentityRepo::new(pool.clone())),
        directory,
    ));

    // Discovered at boot: a console that only reaches its issuer when somebody
    // tries to sign in is one that looks healthy while being unusable.
    let oidc = if config.oidc.issuer.is_empty() {
        None
    } else {
        Some(Arc::new(Oidc::discover(&config.oidc).await?))
    };

    let stores = Arc::new(mount_stores(&config, &pool).await?);
    tracing::info!(count = stores.len(), "stores mounted");

    let cookie_key = session_key(&config)?;

    // Dev mode is on precisely when no issuer is configured. Every
    // authorisation decision is still made, so a local run behaves like
    // production minus the redirect.
    let dev = oidc.is_none().then(|| DevActor {
        handle: if config.oidc.dev_user.is_empty() {
            "dev".to_owned()
        } else {
            config.oidc.dev_user.clone()
        },
        roles: config
            .oidc
            .dev_roles
            .iter()
            .filter_map(|r| Role::parse(r))
            .collect(),
        groups: config.oidc.dev_groups.clone(),
    });
    if let Some(dev) = &dev {
        tracing::warn!(
            user = %dev.handle,
            "no issuer configured; serving as the dev user with no authentication"
        );
    }

    let state = AppState {
        stores,
        access,
        audit,
        tokens: tokens.clone(),
        identity: identity.clone(),
        auth: Arc::new(AuthState {
            tokens,
            identity,
            dev,
            cookie_key: cookie_key.clone(),
        }),
        branding: Arc::new(config.branding.clone()),
        oidc,
        session_hours: config.oidc.session_hours,
        cookie_key,
    };

    let api = tokio::net::TcpListener::bind(normalise(&config.server.address)).await?;
    let metrics = tokio::net::TcpListener::bind(normalise(&config.server.metrics_address)).await?;
    tracing::info!(
        api = %config.server.address,
        metrics = %config.server.metrics_address,
        "listening"
    );

    // Two listeners, because a scrape endpoint publishes what a deployment
    // holds and is almost always less guarded than an API port.
    let handle = telemetry.metrics.clone();
    let api = axum::serve(api, router::build(state)).with_graceful_shutdown(shutdown_signal());
    let metrics =
        axum::serve(metrics, router::metrics(handle)).with_graceful_shutdown(shutdown_signal());

    tokio::try_join!(api.into_future(), metrics.into_future())?;
    Ok(())
}

/// The key the session cookie is encrypted under.
///
/// Generated when unset, which is right for a single-replica dev run and wrong
/// for anything else — several replicas each generating their own means a
/// session minted by one is unreadable by the next, so this warns loudly.
fn session_key(config: &Config) -> eyre::Result<axum_extra::extract::cookie::Key> {
    use base64::Engine as _;

    if config.oidc.session_key.is_empty() {
        tracing::warn!(
            "no oidc.session_key configured; generating one. \
             Sessions will not survive a restart, and replicas will not share them."
        );
        return Ok(axum_extra::extract::cookie::Key::generate());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(config.oidc.session_key.trim())
        .wrap_err("oidc.session_key is not base64")?;
    if raw.len() < 64 {
        eyre::bail!(
            "oidc.session_key decodes to {} bytes; at least 64 are needed",
            raw.len()
        );
    }
    Ok(axum_extra::extract::cookie::Key::from(&raw))
}

/// `:8080` is how a config spells "every interface", which is not an address
/// Rust will parse.
fn normalise(address: &str) -> String {
    if address.starts_with(':') {
        format!("0.0.0.0{address}")
    } else {
        address.to_owned()
    }
}

/// Builds every Store the config declares.
///
/// A Store whose adapter this build does not know is worth refusing to start
/// over: silently serving four of five declared Stores is worse than not
/// starting, because nobody notices the fifth is missing.
async fn mount_stores(config: &Config, pool: &sqlx::PgPool) -> eyre::Result<Registry> {
    let mut mounted = Vec::new();
    for declared in &config.stores {
        let setting = |name: &str| {
            declared
                .settings
                .get(name)
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        };
        let manager: Box<dyn SecretManager> = match declared.kind.as_str() {
            "keyway" => Box::new(OwnStoreService::new(
                &declared.id,
                Arc::new(PostgresOwnStoreRepo::new(pool.clone())),
                keyring_for(declared)?,
            )),
            "gcp" => {
                let project = setting("project")
                    .ok_or_else(|| eyre::eyre!("store {:?} needs a `project`", declared.id))?;
                Box::new(GcpSecretManager::new(project).await?)
            }
            other => {
                return Err(eyre::eyre!(
                    "store {:?} names an unknown type {other:?}; this build has: keyway, gcp",
                    declared.id
                ));
            }
        };
        mounted.push(Store::new(declared.clone(), manager));
    }
    Ok(Registry::new(mounted)?)
}

/// The keys one own Store seals and opens with.
fn keyring_for(declared: &StoreConfig) -> eyre::Result<Keyring> {
    let setting = |name: &str| {
        declared
            .settings
            .get(name)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    };

    let active = setting("key_id").unwrap_or_else(|| "v1".to_owned());
    let mut keys = Vec::new();
    if let Some(key) = setting("key") {
        keys.push((active.clone(), key));
    }
    // Retired keys stay configured for exactly as long as a version sealed
    // under them still exists.
    if let Some(previous) = declared
        .settings
        .get("previous_keys")
        .and_then(serde_norway::Value::as_mapping)
    {
        for (id, key) in previous {
            if let (Some(id), Some(key)) = (id.as_str(), key.as_str()) {
                keys.push((id.to_owned(), key.to_owned()));
            }
        }
    }
    Ok(Keyring::new(active, keys)?)
}

/// Stops accepting, then lets in-flight requests finish. A reveal cut in half
/// is an audit row without an answer.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
