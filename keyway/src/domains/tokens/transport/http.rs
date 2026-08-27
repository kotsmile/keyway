//! The tokens page.
//!
//! Every route here is scoped to the CALLER's own subject, and there is no
//! admin view. That is a deliberate asymmetry with the rest of keyway: an
//! admin sees every secret because secrets are the thing being administered,
//! whereas a list of somebody else's credentials is a target — and seeing it
//! would not let an admin do anything they cannot already do by revoking.

use crate::AppState;
use crate::domains::tokens::entity::Token;
use crate::transport::{ApiError, Caller};
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(list).post(mint))
        .route("/tokens/{id}", axum::routing::delete(revoke))
}

async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
) -> Result<Json<Vec<Token>>, ApiError> {
    Ok(Json(
        state
            .tokens
            .list(actor.handle())
            .await
            .map_err(ApiError::Internal)?,
    ))
}

#[derive(Deserialize)]
struct MintBody {
    name: String,
    /// Bounds the token; 0 or absent means it does not expire.
    ///
    /// Days rather than a timestamp because it is a choice being made now, not
    /// a date being transcribed — and a client computing the instant is a
    /// client that can compute it in the wrong timezone.
    #[serde(default)]
    days: i64,
}

#[derive(Serialize)]
struct MintedView {
    id: String,
    name: String,
    /// The one and only time this exists anywhere.
    token: String,
    expires_at: Option<chrono::DateTime<Utc>>,
}

async fn mint(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Json(body): Json<MintBody>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse as _;

    if body.days < 0 {
        return Err(ApiError::BadRequest("days cannot be negative".to_owned()));
    }
    let expires_at = (body.days > 0).then(|| Utc::now() + Duration::days(body.days));

    let minted = state
        .tokens
        .mint(actor.handle(), &body.name, expires_at)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    tracing::info!(
        token_id = %minted.token.id,
        user = actor.handle(),
        name = %minted.token.name,
        "token issued"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        // no-store on the one response that carries a credential, for the same
        // reason a reveal sets it: nothing on the way back should keep this.
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(MintedView {
            id: minted.token.id.clone(),
            name: minted.token.name.clone(),
            token: minted.plaintext.to_string(),
            expires_at: minted.token.expires_at,
        }),
    )
        .into_response())
}

async fn revoke(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let gone = state
        .tokens
        .revoke(actor.handle(), &id)
        .await
        .map_err(ApiError::Internal)?;

    if !gone {
        // 404 for somebody else's token as well as for one that never existed:
        // a 403 would confirm that the id names a real token, which is a fact
        // nobody has any business learning by guessing.
        return Err(ApiError::NotFound);
    }
    tracing::info!(token_id = %id, user = actor.handle(), "token revoked");
    Ok(axum::http::StatusCode::NO_CONTENT)
}
