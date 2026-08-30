// Package telemetry is traces and metrics.
//
// # What must never appear in either
//
// A metrics endpoint is scraped by a system that is almost always less
// guarded than the API, and a trace is shipped to a collector somebody else
// operates. So:
//
//   - No values, ever. Not in a span attribute, not in a log line.
//   - No secret names as metric labels. A label is a time series per distinct
//     value, so naming secrets there both explodes cardinality and publishes
//     the inventory to anybody who can reach /metrics. Metrics are labelled
//     by Store and by outcome, which are bounded sets.
//   - Secret names in spans only, where access is already scoped to whoever
//     can read traces, and never the payload.
//
// The interesting question for a secrets tool is "who looked at this", and
// that is the audit log's job — not telemetry's. These exist to answer "is it
// up, is it slow, is something being brute-forced".
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Metric names, in one place so a dashboard and the code cannot drift. They
// are the Rust server's names, because the dashboards already exist.
const (
	// NameReveals is reveals served, by store and outcome. The rate that
	// matters most: a step change in it is either an incident or an
	// integration nobody mentioned.
	NameReveals = "keyway_reveals_total"
	// NameAuthFailures is requests that failed to authenticate, by reason. A
	// spike is somebody trying tokens.
	NameAuthFailures = "keyway_auth_failures_total"
	// NameBackendCalls is calls into a backing secret manager, by store and
	// outcome.
	NameBackendCalls = "keyway_backend_calls_total"
	// NameBackendSeconds is how long a backing secret manager took, by store
	// and operation.
	NameBackendSeconds = "keyway_backend_duration_seconds"
	// NameGrants is grants written or removed, by action.
	NameGrants = "keyway_grants_total"
)

// Telemetry is the live instruments. Held for the process's lifetime;
// Shutdown flushes.
type Telemetry struct {
	registry *prometheus.Registry
	traces   *sdktrace.TracerProvider

	reveals        *prometheus.CounterVec
	authFailures   *prometheus.CounterVec
	backendCalls   *prometheus.CounterVec
	backendSeconds *prometheus.HistogramVec
	grants         *prometheus.CounterVec
}

// Init sets up logging, metrics and — only when an endpoint is configured —
// OTLP trace export. A deployment with no collector should not be retrying
// exports into the void.
//
// Logging is structured slog to stderr; KEYWAY_LOG=debug turns per-request
// lines on, the way RUST_LOG did for the Rust server.
func Init(ctx context.Context, serviceName, otlpEndpoint string) (*Telemetry, error) {
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("KEYWAY_LOG"), "debug") {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	registry := prometheus.NewRegistry()
	t := &Telemetry{
		registry: registry,
		reveals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: NameReveals, Help: "Reveals served, by store and outcome.",
		}, []string{"store", "outcome"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: NameAuthFailures, Help: "Requests that failed to authenticate, by reason.",
		}, []string{"reason"}),
		backendCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: NameBackendCalls, Help: "Calls into a backing secret manager, by store and outcome.",
		}, []string{"store", "operation", "outcome"}),
		backendSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: NameBackendSeconds,
			Help: "How long a backing secret manager took, by store and operation.",
			// Latency wants quantiles, not the default bucket set. The same
			// buckets the Rust exporter used.
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		}, []string{"store", "operation"}),
		grants: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: NameGrants, Help: "Grants written or removed, by action.",
		}, []string{"action"}),
	}
	for _, collector := range []prometheus.Collector{
		t.reveals, t.authFailures, t.backendCalls, t.backendSeconds, t.grants,
	} {
		if err := registry.Register(collector); err != nil {
			return nil, fmt.Errorf("registering metrics: %w", err)
		}
	}

	if otlpEndpoint != "" {
		provider, err := traceProvider(ctx, serviceName, otlpEndpoint)
		if err != nil {
			return nil, err
		}
		t.traces = provider
		otel.SetTracerProvider(provider)
	}

	return t, nil
}

// traceProvider builds the OTLP gRPC exporter. An `http://` endpoint means
// plaintext, `https://` means TLS, and a bare host:port is treated as
// plaintext — the local-collector case the Rust tonic exporter served.
func traceProvider(ctx context.Context, serviceName, endpoint string) (*sdktrace.TracerProvider, error) {
	options := []otlptracegrpc.Option{}
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		options = append(options, otlptracegrpc.WithEndpoint(strings.TrimPrefix(endpoint, "https://")))
	case strings.HasPrefix(endpoint, "http://"):
		options = append(options,
			otlptracegrpc.WithEndpoint(strings.TrimPrefix(endpoint, "http://")),
			otlptracegrpc.WithInsecure())
	default:
		options = append(options, otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("building the OTLP exporter for %s: %w", endpoint, err)
	}
	resource, err := sdkresource.Merge(sdkresource.Default(), sdkresource.NewWithAttributes(
		semconv.SchemaURL, semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, fmt.Errorf("building the trace resource: %w", err)
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource),
	), nil
}

// Handler renders /metrics.
func (t *Telemetry) Handler() http.Handler {
	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{})
}

// Shutdown flushes pending spans, so a shutdown is not the last thing lost.
func (t *Telemetry) Shutdown(ctx context.Context) {
	if t.traces == nil {
		return
	}
	if err := t.traces.Shutdown(ctx); err != nil {
		slog.Warn("flushing traces failed", "error", err)
	}
}

// Reveal records a reveal. The store is a label; the secret's name is not.
func (t *Telemetry) Reveal(store, outcome string) {
	t.reveals.WithLabelValues(store, outcome).Inc()
}

// AuthFailure records a rejected credential, by why.
func (t *Telemetry) AuthFailure(reason string) {
	t.authFailures.WithLabelValues(reason).Inc()
}

// BackendCall records one call into a backing secret manager. It is the
// function secrets.ObserveBackendCall is set to at boot.
func (t *Telemetry) BackendCall(store, operation, outcome string, seconds float64) {
	t.backendCalls.WithLabelValues(store, operation, outcome).Inc()
	t.backendSeconds.WithLabelValues(store, operation).Observe(seconds)
}

// Grant records a grant being written or removed.
func (t *Telemetry) Grant(action string) {
	t.grants.WithLabelValues(action).Inc()
}
