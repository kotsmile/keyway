//! The inventory over HTTP.
//!
//! Secrets are addressed by uuid throughout. Resolving one to a (store, name)
//! is this layer's job, and it is deliberately a scan of what the caller can
//! already see — a lookup table would be a second source of truth about where
//! a secret lives.

use crate::AppState;
use crate::domains::access::entity::Level;
use crate::domains::audit::entity::{Action, Record};
use crate::domains::secrets::entity::{Secret, Store, identity};
use crate::transport::{ApiError, Caller};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/stores", get(list_stores))
        .route("/secrets", get(list).post(create))
        .route("/secrets/{id}", get(view).delete(delete))
        .route("/secrets/{id}/value", get(reveal))
        .route("/secrets/{id}/versions", get(versions).post(patch))
        .route("/secrets/{id}/history", get(history))
}

/// A secret as the API reports it: addressed by uuid, and carrying how far
/// this caller gets.
#[derive(Serialize)]
struct SecretView {
    id: Uuid,
    store: String,
    name: String,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    labels: crate::domains::secrets::entity::Metadata,
    #[serde(skip_serializing_if = "String::is_empty")]
    latest_version: String,
    level: Option<Level>,
    /// Why this caller can see it — an owner needs to know they are one.
    basis: String,
}

fn view_of(secret: &Secret, access: &crate::domains::access::entity::Access) -> SecretView {
    SecretView {
        id: identity::id_for(secret),
        store: secret.store.clone(),
        name: secret.name.clone(),
        labels: secret.labels.clone(),
        latest_version: secret.latest_version.clone(),
        level: access.level,
        basis: format!("{:?}", access.basis).to_lowercase(),
    }
}

#[derive(Serialize)]
struct StoreView {
    id: String,
    title: String,
    allow: Vec<crate::config::Verb>,
}

async fn list_stores(
    State(state): State<AppState>,
    Caller(_): Caller,
) -> Result<Json<Vec<StoreView>>, ApiError> {
    Ok(Json(
        state
            .stores
            .all()
            .iter()
            .map(|store| StoreView {
                id: store.id().to_owned(),
                title: store.config().display_title().to_owned(),
                allow: store.config().allow.clone(),
            })
            .collect(),
    ))
}

/// Every secret this caller can see, across every Store.
///
/// A Store that fails is reported as empty rather than failing the whole
/// listing: one unreachable cloud project must not black out the console.
async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
) -> Result<Json<Vec<SecretView>>, ApiError> {
    let now = Utc::now();
    let mut out = Vec::new();

    for store in state.stores.all() {
        let secrets = match store.list().await {
            Ok(secrets) => secrets,
            Err(error) => {
                tracing::warn!(store = store.id(), ?error, "listing failed");
                continue;
            }
        };
        for secret in secrets {
            let access = state
                .access
                .access_for(&actor, &secret.store, &secret.name, now)
                .await
                .map_err(ApiError::Internal)?;
            if access.is_visible() {
                out.push(view_of(&secret, &access));
            }
        }
    }
    Ok(Json(out))
}

/// Finds the secret a uuid names, and how far this caller gets on it.
///
/// Returns [`ApiError::NotFound`] both for a secret that does not exist and
/// for one this caller may not see: a distinguishable answer would let anyone
/// enumerate the inventory.
async fn resolve(
    state: &AppState,
    actor: &crate::domains::identity::entity::Actor,
    id: Uuid,
) -> Result<(Arc<Store>, Secret, crate::domains::access::entity::Access), ApiError> {
    let now = Utc::now();
    for store in state.stores.all() {
        let Ok(secrets) = store.list().await else {
            continue;
        };
        let Some(secret) = secrets.into_iter().find(|s| identity::id_for(s) == id) else {
            continue;
        };
        let access = state
            .access
            .access_for(actor, &secret.store, &secret.name, now)
            .await
            .map_err(ApiError::Internal)?;
        if !access.is_visible() {
            return Err(ApiError::NotFound);
        }
        return Ok((store, secret, access));
    }
    Err(ApiError::NotFound)
}

async fn view(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<SecretView>, ApiError> {
    let (_, secret, access) = resolve(&state, &actor, id).await?;
    Ok(Json(view_of(&secret, &access)))
}

#[derive(Deserialize)]
struct RevealQuery {
    /// One key of a key/value secret. Absent means the whole payload.
    key: Option<String>,
    version: Option<String>,
}

/// Reads a value. Always audited — the reason `reveal` is a word separate from
/// "read".
async fn reveal(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
    Query(query): Query<RevealQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse as _;

    let (store, secret, access) = resolve(&state, &actor, id).await?;

    let permitted = query.key.as_ref().map_or_else(
        || access.allows(Level::Read),
        |key| access.allows_key(Level::Read, key),
    );
    if !permitted {
        return Err(ApiError::Forbidden);
    }

    let payload = store.access(&secret.name, query.version.as_deref()).await?;

    state
        .audit
        .record(
            &actor,
            Record::new(Action::Reveal, &secret.store, &secret.name)
                .version(query.version.as_deref().unwrap_or(&secret.latest_version))
                .keys(query.key.clone()),
        )
        .await
        .map_err(ApiError::Internal)?;

    let body = value_for(&payload, query.key.as_deref())?;
    Ok((
        // Nothing on the way back should keep this.
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response())
}

/// One key of a kv payload, or the payload verbatim.
///
/// A kv secret is JSON by the time it reaches here, which is what lets a
/// backend with native key/value serve one natively and one without not be
/// asked to fake it.
fn value_for(payload: &[u8], key: Option<&str>) -> Result<String, ApiError> {
    let Some(key) = key else {
        return Ok(String::from_utf8_lossy(payload).into_owned());
    };
    let parsed: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| ApiError::BadRequest("this secret has no keys".to_owned()))?;
    parsed
        .get(key)
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
struct CreateBody {
    store: String,
    name: String,
    value: String,
    #[serde(default)]
    note: String,
}

/// Brings a new secret into the inventory, owned by whoever made it.
async fn create(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Json(body): Json<CreateBody>,
) -> Result<Json<SecretView>, ApiError> {
    if !actor.may_create() {
        return Err(ApiError::Forbidden);
    }
    let store = state.stores.get(&body.store).ok_or(ApiError::NotFound)?;

    let mut labels = crate::domains::secrets::entity::Metadata::new();
    labels.insert(
        identity::LABEL.to_owned(),
        identity::derive(&body.store, &body.name).to_string(),
    );
    store.create(&body.name, labels).await?;
    let version = store.add_version(&body.name, body.value.as_bytes()).await?;

    // Ownership before audit: a secret with no owner is one nobody is
    // answerable for, and the window should be as short as possible.
    state
        .access
        .set_owner(&crate::domains::access::entity::Ownership {
            store: body.store.clone(),
            secret: body.name.clone(),
            owner: actor.handle().to_owned(),
            since: Utc::now(),
        })
        .await
        .map_err(ApiError::Internal)?;

    state
        .audit
        .record(
            &actor,
            Record::new(Action::Create, &body.store, &body.name)
                .version(&version.id)
                .note(&body.note),
        )
        .await
        .map_err(ApiError::Internal)?;

    let secret = store.get(&body.name).await?;
    let access = state
        .access
        .access_for(&actor, &body.store, &body.name, Utc::now())
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(view_of(&secret, &access)))
}

#[derive(Deserialize)]
struct PatchBody {
    value: String,
    #[serde(default)]
    note: String,
}

/// Writes a new version.
async fn patch(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchBody>,
) -> Result<Json<crate::domains::secrets::entity::Version>, ApiError> {
    let (store, secret, access) = resolve(&state, &actor, id).await?;
    if !access.allows(Level::Write) {
        return Err(ApiError::Forbidden);
    }

    let version = store
        .add_version(&secret.name, body.value.as_bytes())
        .await?;

    state
        .audit
        .record(
            &actor,
            Record::new(Action::Update, &secret.store, &secret.name)
                .version(&version.id)
                .note(&body.note),
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(version))
}

async fn versions(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate::domains::secrets::entity::Version>>, ApiError> {
    let (store, secret, _) = resolve(&state, &actor, id).await?;
    Ok(Json(store.versions(&secret.name).await?))
}

async fn history(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate::domains::audit::entity::Entry>>, ApiError> {
    let (_, secret, _) = resolve(&state, &actor, id).await?;
    Ok(Json(
        state
            .audit
            .for_secret(&secret.store, &secret.name, 200)
            .await
            .map_err(ApiError::Internal)?,
    ))
}

/// Destroys a secret. Only its owner or an admin, and never from the CLI
/// (ADR-0005).
async fn delete(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    use crate::domains::access::entity::Basis;

    let (store, secret, access) = resolve(&state, &actor, id).await?;
    // Deliberately narrower than `write`: a delegation at write may push a new
    // version, and that is not the same power as losing the secret entirely.
    if !matches!(access.basis, Basis::Owner | Basis::Admin) {
        return Err(ApiError::Forbidden);
    }

    store.delete(&secret.name).await?;
    state
        .audit
        .record(
            &actor,
            Record::new(Action::Delete, &secret.store, &secret.name),
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
