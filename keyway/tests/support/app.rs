//! A whole keyway, in-process, over a real Postgres.
//!
//! Builds the same `AppState` and router `serve` builds, so an integration
//! test exercises the real stack rather than a rehearsal of it.

use keyway::config::StoreConfig;
use keyway::domains::access::AccessService;
use keyway::domains::access::infra::PostgresAccessRepo;
use keyway::domains::audit::AuditService;
use keyway::domains::audit::infra::PostgresAuditRepo;
use keyway::domains::identity::IdentityService;
use keyway::domains::identity::entity::Role;
use keyway::domains::identity::infra::PostgresIdentityRepo;
use keyway::domains::secrets::OwnStoreService;
use keyway::domains::secrets::entity::{Keyring, Registry, SecretManager, Store};
use keyway::domains::secrets::infra::PostgresOwnStoreRepo;
use keyway::domains::tokens::TokenService;
use keyway::domains::tokens::infra::PostgresTokenRepo;
use keyway::transport::auth_middleware::{AuthState, DevActor};
use keyway::{AppState, router};
use sqlx::PgPool;
use std::sync::Arc;

/// 32 bytes of base64.
const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

/// A running keyway, reachable over loopback.
pub struct App {
    pub base: String,
    pub client: reqwest::Client,
    pub pool: PgPool,
}

impl App {
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

/// Starts keyway acting as `dev_user`, with one own Store called `local`.
pub async fn start(pool: PgPool, handle: &str, roles: &[Role], groups: &[&str]) -> App {
    let store_config: StoreConfig = serde_norway::from_str(
        "id: local\ntype: keyway\ntitle: Local\nallow: [read, edit, create, delete]\n",
    )
    .expect("a valid store config");

    let keyring = Keyring::new("v1", [("v1".to_owned(), KEY.to_owned())]).expect("a valid keyring");
    let manager: Box<dyn SecretManager> = Box::new(OwnStoreService::new(
        "local",
        Arc::new(PostgresOwnStoreRepo::new(pool.clone())),
        keyring,
    ));
    let registry = Registry::new([Store::new(store_config, manager)]).expect("a valid registry");

    let tokens = Arc::new(TokenService::new(Arc::new(PostgresTokenRepo::new(
        pool.clone(),
    ))));
    let identity = Arc::new(IdentityService::new(
        Arc::new(PostgresIdentityRepo::new(pool.clone())),
        None,
    ));

    let cookie_key = axum_extra::extract::cookie::Key::generate();
    let state = AppState {
        stores: Arc::new(registry),
        access: Arc::new(AccessService::new(Arc::new(PostgresAccessRepo::new(
            pool.clone(),
        )))),
        audit: Arc::new(AuditService::new(Arc::new(PostgresAuditRepo::new(
            pool.clone(),
        )))),
        tokens: tokens.clone(),
        identity: identity.clone(),
        auth: Arc::new(AuthState {
            tokens,
            identity,
            dev: Some(DevActor {
                handle: handle.to_owned(),
                roles: roles.to_vec(),
                groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            }),
            cookie_key: cookie_key.clone(),
        }),
        branding: Arc::new(keyway::config::Branding::default()),
        oidc: None,
        session_hours: 8,
        cookie_key,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let addr = listener.local_addr().expect("a bound address");

    tokio::spawn(async move {
        let _ = axum::serve(listener, router::build(state)).await;
    });

    App {
        base: format!("http://{addr}"),
        client: reqwest::Client::new(),
        pool,
    }
}
