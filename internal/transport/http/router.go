// Where every domain's routes are mounted.
package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Build is everything keyway serves on its API port.
func Build(state *State) http.Handler {
	r := chi.NewRouter()
	r.Use(logRequests)

	// Unauthenticated on purpose: a load balancer holds no credential, and an
	// unhealthy pod must be able to say so.
	r.Get("/healthz", healthz)

	r.Route("/api", func(api chi.Router) {
		// The auth middleware is the Rust Caller extractor, hoisted: every
		// /api handler took one, so every /api route resolves one.
		api.Use(state.Auth.Middleware)
		mountSecrets(api, state)
		mountAccess(api, state)
		mountTokens(api, state)
		mountAudit(api, state)
		mountIdentityAPI(api, state)
	})

	// Sign-in lives at the root, not under /api: a browser is redirected
	// here, and /api is for things that speak JSON.
	mountIdentity(r, state)

	return r
}

// Metrics is the metrics listener.
//
// Its own handler on its own port, with no shared state and no auth
// middleware: it must keep answering a scrape when the database is down,
// which is exactly when somebody needs the numbers.
func Metrics(render http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Handle("/metrics", render)
	r.Get("/healthz", healthz)
	return r
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

// logRequests is the Go stand-in for tower-http's TraceLayer: one structured
// line per request, at debug so a production filter can drop it wholesale.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		slog.Debug("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration", time.Since(started),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
