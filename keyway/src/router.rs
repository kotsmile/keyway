//! Where every domain's routes are mounted.

use crate::AppState;
use axum::Router;
use axum::routing::get;
use tower_http::trace::TraceLayer;

/// Everything keyway serves on its API port.
pub fn build(state: AppState) -> Router {
    let api = Router::new()
        .merge(crate::domains::secrets::transport::http::routes())
        .merge(crate::domains::access::transport::http::routes())
        .merge(crate::domains::tokens::transport::http::routes())
        .merge(crate::domains::audit::transport::http::routes());

    Router::new()
        // Unauthenticated on purpose: a load balancer holds no credential, and
        // an unhealthy pod must be able to say so.
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The metrics listener.
///
/// Its own Router on its own port, with no shared state and no auth extractor:
/// it must keep answering a scrape when the database is down, which is exactly
/// when somebody needs the numbers.
pub fn metrics(handle: metrics_exporter_prometheus::PrometheusHandle) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
}
