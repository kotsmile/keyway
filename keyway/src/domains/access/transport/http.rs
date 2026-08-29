//! Grants over HTTP.
//!
//! Delegating is scriptable and destroying is not (ADR-0005): a mistaken grant
//! is visible in the audit log and revocable in a click, whereas a deleted
//! secret has no undo.

use crate::AppState;
use crate::domains::access::entity::{Basis, Delegation, Level, Subject};
use crate::domains::audit::entity::{Action, Record};
use crate::domains::secrets::entity::identity;
use crate::transport::{ApiError, Caller};
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/secrets/{id}/grants", get(list).post(delegate))
        .route(
            "/secrets/{id}/grants/{grant}",
            axum::routing::delete(revoke),
        )
}

#[derive(Serialize)]
struct GrantView {
    id: Uuid,
    subject_kind: String,
    subject: String,
    level: Level,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keys: Vec<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
}

impl From<Delegation> for GrantView {
    fn from(grant: Delegation) -> Self {
        Self {
            id: grant.id,
            subject_kind: grant.subject.kind().to_owned(),
            subject: grant.subject.id().to_owned(),
            level: grant.level,
            keys: grant.keys,
            granted_by: grant.granted_by,
            granted_at: grant.granted_at,
            expires_at: grant.expires_at,
            note: grant.note,
        }
    }
}

/// Who can see this secret — the list the whole mechanism exists to make
/// readable.
async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<GrantView>>, ApiError> {
    let (store, secret) = locate(&state, &actor, id).await?;
    Ok(Json(
        state
            .access
            .grants_on(&store, &secret)
            .await
            .map_err(ApiError::Internal)?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[derive(Deserialize)]
struct DelegateBody {
    /// `user` or `group`, always explicit — a team called `sre` and a person
    /// called `sre` are different subjects (ADR-0003).
    subject_kind: String,
    subject: String,
    level: String,
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    days: i64,
    #[serde(default)]
    note: String,
}

async fn delegate(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<DelegateBody>,
) -> Result<Json<GrantView>, ApiError> {
    let (store, secret) = locate(&state, &actor, id).await?;

    // Only an owner or an admin hands out sight of a secret. A delegation at
    // `write` does not carry the right to re-delegate: that belongs to
    // ownership, which is a different act with a different audit line.
    let access = state
        .access
        .access_for(&actor, &store, &secret, Utc::now())
        .await
        .map_err(ApiError::Internal)?;
    if !matches!(access.basis, Basis::Owner | Basis::Admin) {
        return Err(ApiError::Forbidden);
    }

    let subject = match body.subject_kind.as_str() {
        "user" => Subject::User(body.subject.clone()),
        "group" => Subject::Group(body.subject.clone()),
        other => {
            return Err(ApiError::BadRequest(format!(
                "subject_kind must be user or group, not {other:?}"
            )));
        }
    };
    let level: Level =
        body.level
            .parse()
            .map_err(|e: crate::domains::access::entity::UnknownLevel| {
                ApiError::BadRequest(e.to_string())
            })?;

    let grant = Delegation {
        id: Uuid::new_v4(),
        store: store.clone(),
        secret: secret.clone(),
        subject,
        level,
        keys: body.keys,
        granted_by: actor.handle().to_owned(),
        granted_at: Utc::now(),
        expires_at: (body.days > 0).then(|| Utc::now() + Duration::days(body.days)),
        note: body.note,
    };

    state
        .access
        .delegate(&grant)
        .await
        .map_err(ApiError::Internal)?;

    state
        .audit
        .record(
            &actor,
            Record::new(Action::Delegate, id, &store, &secret)
                .subject(&body.subject)
                .keys(grant.keys.clone())
                .note(&grant.note),
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(grant.into()))
}

async fn revoke(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, grant_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let (store, secret) = locate(&state, &actor, id).await?;

    let access = state
        .access
        .access_for(&actor, &store, &secret, Utc::now())
        .await
        .map_err(ApiError::Internal)?;
    if !matches!(access.basis, Basis::Owner | Basis::Admin) {
        return Err(ApiError::Forbidden);
    }

    let subject = state
        .access
        .grants_on(&store, &secret)
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .find(|g| g.id == grant_id)
        .map(|g| g.subject.id().to_owned())
        .ok_or(ApiError::NotFound)?;

    if !state
        .access
        .revoke(grant_id)
        .await
        .map_err(ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }

    state
        .audit
        .record(
            &actor,
            Record::new(Action::Revoke, id, &store, &secret).subject(&subject),
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Which secret a uuid names, for a caller who can already see it.
async fn locate(
    state: &AppState,
    actor: &crate::domains::identity::entity::Actor,
    id: Uuid,
) -> Result<(String, String), ApiError> {
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
        return Ok((secret.store, secret.name));
    }
    Err(ApiError::NotFound)
}
