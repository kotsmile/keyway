// Package transport is how keyway is reached, and what every route shares.
//
// It carries the Rust crate's transport module and its AppState: the error
// vocabulary, the session cookie, the auth middleware, and the State every
// handler is given. The handlers themselves live with their domains, in
// internal/domains/*/transport, the way the Rust ones did.
package transport

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/kotsmile/keyway/internal/config"
	"github.com/kotsmile/keyway/internal/domains/access"
	"github.com/kotsmile/keyway/internal/domains/audit"
	"github.com/kotsmile/keyway/internal/domains/identity"
	identityinfra "github.com/kotsmile/keyway/internal/domains/identity/infra"
	"github.com/kotsmile/keyway/internal/domains/secrets"
	"github.com/kotsmile/keyway/internal/domains/tokens"
)

// State is what every handler is given.
type State struct {
	Stores   *secrets.Registry
	Access   *access.Service
	Audit    *audit.Service
	Tokens   *tokens.Service
	Identity *identity.Service
	Auth     *Auth
	Branding config.Branding
	// Oidc is the configured issuer, nil in dev mode.
	Oidc         *identityinfra.Oidc
	SessionHours int64
	// Codec seals the session and pending-login cookies.
	Codec *Codec
}

// Now is the shared clock, injectable per Auth for tests; handlers reach it
// through the auth state so the whole request agrees on one source of time.
func (s *State) Now() time.Time {
	return s.Auth.now()
}

// Handler adapts a handler that returns its failure, so every route reports
// errors through exactly one door.
func Handler(fn func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			WriteError(w, err)
		}
	}
}

// DecodeJSON reads a request body the way axum's Json extractor did, statuses
// included, because the Rust integration suite pinned them: a missing or
// wrong Content-Type is 415, JSON that does not parse is 400, and JSON that
// parses but does not fit the shape is 422.
func DecodeJSON(r *http.Request, into any) error {
	mediatype, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediatype != "application/json" {
		return &ApiError{
			Status:  http.StatusUnsupportedMediaType,
			Message: "Expected request with `Content-Type: application/json`",
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 2<<20))
	if err != nil {
		return BadRequest("reading the request body failed")
	}
	if err := json.Unmarshal(body, into); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return &ApiError{Status: http.StatusUnprocessableEntity, Message: err.Error()}
		}
		return BadRequest(err.Error())
	}
	return nil
}

// MissingField is the 422 a missing required field earns — what serde's
// non-defaulted fields refused. Handlers decode required fields into
// pointers and report the first nil one through this.
func MissingField(name string) error {
	return &ApiError{
		Status:  http.StatusUnprocessableEntity,
		Message: "missing field `" + name + "`",
	}
}
