// What a failure looks like on the wire.
//
// The guiding rule for a secrets console: a response must not teach a caller
// anything they could not already ask for. An unknown Store, an unknown
// secret and a secret somebody may not see are all 404 — a 403 would confirm
// that the thing exists, which is a fact worth guessing for.

package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
)

// ApiError is a failure as the API reports it: a status, and the one sentence
// the caller gets. The Rust ApiError enum, flattened — Go has no need for the
// variants once each carries its status and message.
type ApiError struct {
	Status  int
	Message string
	// Err is the failure behind an internal error. Logged in full and
	// reported as nothing: the detail is for an operator reading logs, not
	// for whoever provoked it.
	Err error
}

func (e *ApiError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func (e *ApiError) Unwrap() error { return e.Err }

// NotFound is no such secret — or one this caller may not see. Deliberately
// the same answer.
func NotFound() *ApiError {
	return &ApiError{Status: http.StatusNotFound, Message: "not found"}
}

// Forbidden is signed in, but not far enough for this. Used only where the
// caller already knows the thing exists.
func Forbidden() *ApiError {
	return &ApiError{Status: http.StatusForbidden, Message: "forbidden"}
}

// Unauthorized is no acceptable credential at all.
func Unauthorized() *ApiError {
	return &ApiError{Status: http.StatusUnauthorized, Message: "unauthorized"}
}

// BadRequest is a request the caller can fix, told how.
func BadRequest(message string) *ApiError {
	return &ApiError{Status: http.StatusBadRequest, Message: message}
}

// Refused is a verb the deployment did not grant on this Store, or a secret a
// reconciler owns. Reported as it is written, because its whole value is
// telling the reader what to go and change. 409, as the Rust server answered.
func Refused(message string) *ApiError {
	return &ApiError{Status: http.StatusConflict, Message: message}
}

// Internal is everything nobody outside should learn about.
func Internal(err error) *ApiError {
	return &ApiError{Status: http.StatusInternalServerError, Message: "internal error", Err: err}
}

// FromStoreError maps a Store's failure to the wire, the way the Rust
// From<StoreError> did.
//
// A refusal — a missing verb, a protected secret — keeps its own words and
// answers 409. An unknown secret or version is 404. Everything else,
// including a backend failure and a name the backend refused, is internal:
// the Rust server answered 500 there, so the Go one does too.
func FromStoreError(err error) *ApiError {
	var notAllowed *secretsservice.NotAllowedError
	var protected *secretsservice.ProtectedError
	var noVersion *secretsentity.NoSuchVersionError
	switch {
	case errors.As(err, &notAllowed), errors.As(err, &protected):
		return Refused(err.Error())
	case errors.Is(err, secretsentity.ErrNotFound), errors.As(err, &noVersion):
		return NotFound()
	default:
		return Internal(err)
	}
}

// WriteError reports a failure on the wire as `{ "error": … }`.
//
// Anything that is not already an ApiError went through a Store, so the Store
// mapping is the fallback — and its own fallback is a 500 that logs the full
// error and reports nothing.
func WriteError(w http.ResponseWriter, err error) {
	var api *ApiError
	if !errors.As(err, &api) {
		api = FromStoreError(err)
	}
	if api.Err != nil {
		slog.Error("request failed", "error", api.Err)
	}
	writeJSON(w, api.Status, struct {
		Error string `json:"error"`
	}{Error: api.Message})
}

// writeJSON writes one JSON body with its status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// An encode failure here has nowhere left to report to; the status line
	// already went out.
	_ = json.NewEncoder(w).Encode(body)
}

// WriteJSON writes a 200 with one JSON body — what almost every handler ends
// with.
func WriteJSON(w http.ResponseWriter, body any) {
	writeJSON(w, http.StatusOK, body)
}

// WriteJSONStatus writes a JSON body under a chosen status.
func WriteJSONStatus(w http.ResponseWriter, status int, body any) {
	writeJSON(w, status, body)
}
