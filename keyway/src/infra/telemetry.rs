//! Traces and metrics.
//!
//! # What must never appear in either
//!
//! A metrics endpoint is scraped by a system that is almost always less
//! guarded than the API, and a trace is shipped to a collector somebody else
//! operates. So:
//!
//! - **No values, ever.** Not in a span field, not in an event.
//! - **No secret names as metric labels.** A label is a time series per
//!   distinct value, so naming secrets there both explodes cardinality and
//!   publishes the inventory to anybody who can reach `/metrics`. Metrics are
//!   labelled by Store and by outcome, which are bounded sets.
//! - **Secret names in spans only**, where access is already scoped to whoever
//!   can read traces, and never the payload.
//!
//! The interesting question for a secrets tool is "who looked at this", and
//! that is the audit log's job — not telemetry's. These exist to answer "is it
//! up, is it slow, is something being brute-forced".

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry_otlp::WithExportConfig as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Registry};

/// Metric names, in one place so a dashboard and the code cannot drift.
pub mod names {
    /// Reveals served, by store and outcome. The rate that matters most: a
    /// step change in it is either an incident or an integration nobody
    /// mentioned.
    pub const REVEALS: &str = "keyway_reveals_total";
    /// Requests that failed to authenticate, by reason. A spike is somebody
    /// trying tokens.
    pub const AUTH_FAILURES: &str = "keyway_auth_failures_total";
    /// Calls into a backing secret manager, by store and outcome.
    pub const BACKEND_CALLS: &str = "keyway_backend_calls_total";
    /// How long a backing secret manager took, by store and operation.
    pub const BACKEND_SECONDS: &str = "keyway_backend_duration_seconds";
    /// Grants written or removed, by action.
    pub const GRANTS: &str = "keyway_grants_total";
}

/// Live telemetry. Held for the process's lifetime; dropping it flushes.
pub struct Telemetry {
    /// What `/metrics` renders from.
    pub metrics: PrometheusHandle,
    traces: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Telemetry {
    /// Flushes pending spans, so a shutdown is not the last thing lost.
    pub fn shutdown(&self) {
        if let Some(provider) = &self.traces
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(?error, "flushing traces failed");
        }
    }
}

/// Sets up tracing and metrics.
///
/// OTLP export is on only when an endpoint is configured: a deployment with no
/// collector should not be retrying exports into the void.
///
/// # Errors
///
/// When the Prometheus recorder cannot be installed, or an OTLP endpoint is
/// configured but unusable.
pub fn init(service_name: &str, otlp_endpoint: Option<&str>) -> eyre::Result<Telemetry> {
    let recorder = PrometheusBuilder::new()
        // Latency wants quantiles, not the default bucket set.
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(names::BACKEND_SECONDS.to_owned()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )?
        .install_recorder()?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,keyway=debug,tower_http=debug"));
    let fmt = tracing_subscriber::fmt::layer().with_target(false);

    let traces = if let Some(endpoint) = otlp_endpoint {
        {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name(service_name.to_owned())
                        .build(),
                )
                .build();
            let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "keyway");
            opentelemetry::global::set_tracer_provider(provider.clone());

            Registry::default()
                .with(filter)
                .with(fmt)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            Some(provider)
        }
    } else {
        Registry::default().with(filter).with(fmt).init();
        None
    };

    Ok(Telemetry {
        metrics: recorder,
        traces,
    })
}

/// Records a reveal. The store is a label; the secret's name is not.
pub fn reveal(store: &str, outcome: &'static str) {
    metrics::counter!(names::REVEALS, "store" => store.to_owned(), "outcome" => outcome)
        .increment(1);
}

/// Records a rejected credential, by why.
pub fn auth_failure(reason: &'static str) {
    metrics::counter!(names::AUTH_FAILURES, "reason" => reason).increment(1);
}

/// Records one call into a backing secret manager.
pub fn backend_call(store: &str, operation: &'static str, outcome: &'static str, seconds: f64) {
    metrics::counter!(
        names::BACKEND_CALLS,
        "store" => store.to_owned(),
        "operation" => operation,
        "outcome" => outcome
    )
    .increment(1);
    metrics::histogram!(
        names::BACKEND_SECONDS,
        "store" => store.to_owned(),
        "operation" => operation
    )
    .record(seconds);
}

/// Records a grant being written or removed.
pub fn grant(action: &'static str) {
    metrics::counter!(names::GRANTS, "action" => action).increment(1);
}
