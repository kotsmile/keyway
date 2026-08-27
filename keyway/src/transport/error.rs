//! What a failure looks like on the wire.
//!
//! The guiding rule for a secrets console: a response must not teach a caller
//! anything they could not already ask for. An unknown Store, an unknown
//! secret and a secret somebody may not see are all 404 — a 403 would confirm
//! that the thing exists, which is a fact worth guessing for.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// No such secret — or one this caller may not see. Deliberately the same
    /// answer.
    #[error("not found")]
    NotFound,
    /// Signed in, but not far enough for this. Used only where the caller
    /// already knows the thing exists.
    #[error("forbidden")]
    Forbidden,
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    BadRequest(String),
    /// The deployment did not grant this verb on this Store, or a reconciler
    /// owns the secret. Reported as it is written, because its whole value is
    /// telling the reader what to go and change.
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

#[derive(Serialize)]
struct Body {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Refused(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // An internal failure is logged in full and reported as nothing: the
        // detail is for an operator reading logs, not for whoever provoked it.
        let message = match &self {
            ApiError::Internal(report) => {
                tracing::error!(error = ?report, "request failed");
                "internal error".to_owned()
            }
            other => other.to_string(),
        };

        (status, Json(Body { error: message })).into_response()
    }
}

impl From<crate::domains::secrets::entity::StoreError> for ApiError {
    fn from(error: crate::domains::secrets::entity::StoreError) -> Self {
        use crate::domains::secrets::entity::{BackendError, StoreError};
        match error {
            // Both name what a deployment or a reconciler decided, and both
            // are worth reading: they say what to change.
            StoreError::NotAllowed { .. } | StoreError::Protected { .. } => {
                Self::Refused(error.to_string())
            }
            StoreError::Backend(BackendError::NotFound | BackendError::NoSuchVersion(_)) => {
                Self::NotFound
            }
            StoreError::Backend(other) => Self::Internal(eyre::eyre!(other)),
        }
    }
}
