package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
)

// wireError is what a client reads back: the status line and the one-line
// `{ "error": … }` body.
func wireError(t *testing.T, err error) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	WriteError(recorder, err)

	require.Equal(t, "application/json",
		recorder.Header().Get("Content-Type"), "failures are JSON")
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	return recorder.Code, body.Error
}

// TestStatusMappingMatchesTheRustServer pins the error.rs table: every
// ApiError variant and every StoreError arm answers the status the Rust
// server answered, with the same body discipline — a refusal keeps its own
// words, an internal failure reports nothing.
func TestStatusMappingMatchesTheRustServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantMessage string
	}{
		{"not found", NotFound(), http.StatusNotFound, "not found"},
		{"forbidden", Forbidden(), http.StatusForbidden, "forbidden"},
		{"unauthorized", Unauthorized(), http.StatusUnauthorized, "unauthorized"},
		{"bad request keeps its words", BadRequest("state did not match"),
			http.StatusBadRequest, "state did not match"},
		{"refused keeps its words", Refused("store \"prod\" does not allow delete"),
			http.StatusConflict, "store \"prod\" does not allow delete"},
		{"internal reports nothing", Internal(errors.New("pq: connection refused")),
			http.StatusInternalServerError, "internal error"},
		{
			// StoreError::NotAllowed → Refused → 409, wording intact: its whole
			// value is telling the reader what to go and change.
			"a verb the deployment did not grant",
			&secretsservice.NotAllowedError{Store: "prod", Verb: "delete"},
			http.StatusConflict,
			(&secretsservice.NotAllowedError{Store: "prod", Verb: "delete"}).Error(),
		},
		{
			// StoreError::Protected → Refused → 409.
			"a secret a reconciler owns",
			&secretsservice.ProtectedError{Name: "db-password", Marker: "argocd.argoproj.io/instance"},
			http.StatusConflict,
			(&secretsservice.ProtectedError{Name: "db-password", Marker: "argocd.argoproj.io/instance"}).Error(),
		},
		{
			// Backend(NotFound) → 404, indistinguishable from "may not see".
			"an unknown secret", secretsentity.ErrNotFound,
			http.StatusNotFound, "not found",
		},
		{
			// Backend(NoSuchVersion) → 404.
			"an unknown version", &secretsentity.NoSuchVersionError{Version: "7"},
			http.StatusNotFound, "not found",
		},
		{
			// Backend(other) → 500, detail withheld: it names infrastructure.
			"a backend call that failed",
			secretsentity.Backend("listing lockbox", errors.New("iam: 503")),
			http.StatusInternalServerError, "internal error",
		},
		{
			// Backend(Invalid) → 500, as the Rust match's `other` arm answered.
			"a name the backend refused", &secretsentity.InvalidNameError{Name: "a/b"},
			http.StatusInternalServerError, "internal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, message := wireError(t, tt.err)
			assert.Equal(t, tt.wantStatus, status)
			assert.Equal(t, tt.wantMessage, message)
		})
	}
}

// TestAWrappedStoreErrorStillMaps proves the mapping survives fmt.Errorf
// wrapping, since a Store's failure crosses two layers before the wire.
func TestAWrappedStoreErrorStillMaps(t *testing.T) {
	t.Parallel()
	status, _ := wireError(t, &ApiError{Status: http.StatusNotFound, Message: "not found",
		Err: secretsentity.ErrNotFound})
	assert.Equal(t, http.StatusNotFound, status)

	status, message := wireError(t, errors.Join(secretsentity.ErrNotFound))
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "not found", message)
}
