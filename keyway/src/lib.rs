//! The keyway backend.
//!
//! Laid out by domain rather than by technical layer. Each domain owns its
//! `entity` (pure types and rules, no I/O), its `infra` (the adapters that
//! implement the ports the domain declares), and its `transport` (how it is
//! reached). A domain's `mod.rs` holds its service and the repository traits
//! that service is generic over, so the rules can be tested with no database
//! and no network.

pub mod config;
pub mod container;
pub mod domains;
pub mod infra;
pub mod router;
pub mod transport;

use axum::extract::FromRef;
use std::sync::Arc;

/// What every handler is given.
///
/// Concrete types come from [`container`], so a handler names a service rather
/// than an implementation.
#[derive(Clone)]
pub struct AppState {
    pub stores: Arc<domains::secrets::entity::Registry>,
    pub access: container::Access,
    pub audit: container::Audit,
    pub tokens: container::Tokens,
    pub identity: container::Identity,
    pub auth: Arc<transport::AuthState>,
    pub branding: Arc<config::Branding>,
    /// The configured issuer, absent in dev mode.
    pub oidc: Option<Arc<domains::identity::infra::Oidc>>,
    pub session_hours: i64,
    /// Signs and encrypts the session cookie.
    pub cookie_key: axum_extra::extract::cookie::Key,
}

impl FromRef<AppState> for axum_extra::extract::cookie::Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

impl FromRef<AppState> for Arc<transport::AuthState> {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}
