//! The audit feed.

use crate::AppState;
use crate::domains::audit::entity::Entry;
use crate::transport::{ApiError, Caller};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(feed))
}

#[derive(Deserialize)]
struct FeedQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    /// Keyset rather than an offset: the feed grows while somebody is reading
    /// it, and an offset would silently repeat or skip rows.
    before: Option<i64>,
}

fn default_limit() -> i64 {
    100
}

/// Everything, newest first — admin only.
///
/// The one screen in keyway that shows what everybody else has been doing, so
/// it is the one that needs a fence of its own.
async fn feed(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Query(query): Query<FeedQuery>,
) -> Result<Json<Vec<Entry>>, ApiError> {
    if !actor.is_admin() {
        return Err(ApiError::Forbidden);
    }
    let limit = query.limit.clamp(1, 500);
    Ok(Json(
        state
            .audit
            .feed(limit, query.before)
            .await
            .map_err(ApiError::Internal)?,
    ))
}
