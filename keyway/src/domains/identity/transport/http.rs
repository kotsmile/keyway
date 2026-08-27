//! Signing in and out.

use crate::AppState;
use crate::transport::session::Session;
use crate::transport::{ApiError, Caller};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Where the details of a redirect in progress are kept while the caller is at
/// the issuer.
///
/// In a cookie rather than server memory, so a sign-in survives hitting a
/// different replica than the one that started it.
const PENDING_COOKIE: &str = "keyway_pending";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout))
        .route("/api/me", get(me))
}

#[derive(Serialize, Deserialize)]
struct Pending {
    csrf: String,
    nonce: String,
    pkce_verifier: String,
}

/// Sends somebody to their identity provider.
async fn login(State(state): State<AppState>, jar: PrivateCookieJar) -> Result<Response, ApiError> {
    let Some(oidc) = &state.oidc else {
        return Err(ApiError::BadRequest(
            "this deployment has no issuer configured".to_owned(),
        ));
    };

    let pending = oidc.start();
    let cookie = Cookie::build((
        PENDING_COOKIE,
        serde_json::to_string(&Pending {
            csrf: pending.csrf,
            nonce: pending.nonce,
            pkce_verifier: pending.pkce_verifier,
        })
        .map_err(|e| ApiError::Internal(e.into()))?,
    ))
    .path("/")
    .http_only(true)
    .secure(true)
    // Lax rather than Strict: the issuer redirects back with a GET, and Strict
    // would withhold the cookie on exactly that request.
    .same_site(SameSite::Lax)
    .max_age(time::Duration::minutes(10))
    .build();

    Ok((jar.add(cookie), Redirect::to(&pending.authorize_url)).into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Where the issuer sends them back.
async fn callback(
    State(app): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let Some(oidc) = &app.oidc else {
        return Err(ApiError::BadRequest("no issuer configured".to_owned()));
    };

    if let Some(error) = query.error {
        // The issuer refused. Its wording is the useful part.
        return Err(ApiError::BadRequest(format!("sign-in refused: {error}")));
    }

    let pending: Pending = jar
        .get(PENDING_COOKIE)
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| ApiError::BadRequest("this sign-in expired; start again".to_owned()))?;

    // Without this a third party could hand somebody a callback url and sign
    // them in as an account of the attacker's choosing.
    if query.state.as_deref() != Some(pending.csrf.as_str()) {
        return Err(ApiError::BadRequest("state did not match".to_owned()));
    }
    let code = query
        .code
        .ok_or_else(|| ApiError::BadRequest("no code returned".to_owned()))?;

    let signed_in = oidc
        .finish(&code, &pending.nonce, &pending.pkce_verifier)
        .await
        .map_err(ApiError::Internal)?;

    // Remembering the claim is what lets an API token act as this person in
    // full later on (ADR-0004).
    app.identity
        .sign_in(
            &signed_in.handle,
            signed_in.groups.clone(),
            &signed_in.email,
            &signed_in.name,
            Utc::now(),
        )
        .await
        .map_err(ApiError::Internal)?;

    tracing::info!(user = %signed_in.handle, groups = signed_in.groups.len(), "signed in");

    let session = Session {
        handle: signed_in.handle,
        groups: signed_in.groups,
        roles: signed_in
            .roles
            .iter()
            .map(|r| r.as_str().to_owned())
            .collect(),
        expires_at: Utc::now() + Duration::hours(app.session_hours),
    };

    let jar = jar
        .remove(Cookie::from(PENDING_COOKIE))
        .add(session.into_cookie(app.session_hours));
    Ok((jar, Redirect::to("/")).into_response())
}

/// Drops the session cookie.
///
/// keyway holds no server-side session to invalidate, so this is the whole of
/// signing out here. An API token is revoked separately — deleting the cookie
/// does not touch one.
async fn logout(jar: PrivateCookieJar) -> Response {
    (jar.remove(Cookie::from(Session::COOKIE)), Redirect::to("/")).into_response()
}

#[derive(Serialize)]
struct Me {
    handle: String,
    groups: Vec<String>,
    roles: Vec<String>,
    is_admin: bool,
    may_create: bool,
    /// Whether a Directory is configured. The console warns when delegating to
    /// a group without one, because an API token cannot see such a grant.
    directory: bool,
    branding: Branding,
}

#[derive(Serialize)]
struct Branding {
    name: String,
    logo: String,
    favicon: String,
    accent: String,
}

/// Who the caller is, and what the console should look like.
async fn me(State(state): State<AppState>, Caller(actor): Caller) -> Json<Me> {
    Json(Me {
        handle: actor.handle().to_owned(),
        groups: actor.group_names(),
        roles: actor.role_names(),
        is_admin: actor.is_admin(),
        may_create: actor.may_create(),
        directory: state.identity.has_directory(),
        branding: Branding {
            name: state.branding.name.clone(),
            logo: state.branding.logo.clone(),
            favicon: state.branding.favicon.clone(),
            accent: state.branding.accent.clone(),
        },
    })
}
