//! Turning a request into an [`Actor`].
//!
//! Three doors, resolved in one place so no handler has to know which one a
//! request came through:
//!
//! 1. an **API token** in `Authorization: Bearer kw-…`, acting as the person
//!    who minted it (ADR-0004);
//! 2. a **browser session** (#5);
//! 3. **dev mode** — with no issuer configured, keyway acts as the configured
//!    user. Every authorisation decision is still made, so a local run behaves
//!    like production minus the redirect.

use crate::container;
use crate::domains::identity::entity::{Actor, Role};
use crate::transport::ApiError;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use chrono::Utc;
use std::sync::Arc;

/// What resolving a caller needs.
#[derive(Clone)]
pub struct AuthState {
    pub tokens: container::Tokens,
    pub identity: container::Identity,
    /// Who a local run acts as. `None` once an issuer is configured.
    pub dev: Option<DevActor>,
}

/// The identity a dev-mode run assumes.
#[derive(Clone, Debug)]
pub struct DevActor {
    pub handle: String,
    pub roles: Vec<Role>,
    pub groups: Vec<String>,
}

/// Who is asking, extracted once per request.
///
/// A handler takes this rather than reading headers, so "which door was this"
/// is answered in exactly one place.
pub struct Caller(pub Actor);

impl<S> FromRequestParts<S> for Caller
where
    S: Send + Sync,
    Arc<AuthState>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = <Arc<AuthState> as FromRef<S>>::from_ref(state);

        if let Some(presented) = bearer(parts) {
            return resolve_token(&auth, presented).await.map(Caller);
        }

        // No credential. In dev mode that is the configured user; otherwise it
        // is nobody.
        auth.dev
            .as_ref()
            .map(|dev| {
                Caller(Actor::new(
                    dev.handle.clone(),
                    dev.groups.clone(),
                    dev.roles.clone(),
                ))
            })
            .ok_or(ApiError::Unauthorized)
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn resolve_token(auth: &AuthState, presented: &str) -> Result<Actor, ApiError> {
    let now = Utc::now();
    let verified = auth
        .tokens
        .verify(presented, now)
        .await
        .map_err(ApiError::Internal)?;

    // Every rejection reports the same way. Which one it was goes to the log,
    // because "that id exists but the secret is wrong" is a fact worth
    // guessing for.
    let token = match verified {
        Ok(token) => token,
        Err(reason) => {
            tracing::info!(?reason, "token rejected");
            return Err(ApiError::Unauthorized);
        }
    };

    // Roles are not carried by the token: it acts as its holder. Without a
    // Directory a token's roles are empty, which is deliberate — a role opens
    // no secret anyway (ADR-0002), and the grants addressed to the holder are
    // what matter.
    let actor = auth
        .identity
        .actor_for_token(&token.subject, Vec::new(), &token.id)
        .await
        .map_err(ApiError::Internal)?;

    actor.ok_or_else(|| {
        // Only reachable with a Directory configured: the account is disabled
        // or gone, which is exactly the property a Directory buys back.
        tracing::info!(subject = %token.subject, "token holder is no longer active");
        ApiError::Unauthorized
    })
}
