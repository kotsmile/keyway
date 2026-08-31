// The rest of the Rust HTTP suite (keyway/tests/api.rs), carried over for the
// parity gate: every flow that needed TWO callers over one state, the
// External Secrets read shapes, and the malformed-body statuses axum's Json
// extractor pinned.
package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/config"
	accessservice "github.com/kotsmile/keyway/internal/access/service"
	auditentity "github.com/kotsmile/keyway/internal/audit/entity"
	auditservice "github.com/kotsmile/keyway/internal/audit/service"
	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
)

// world is one deployment's state, shared by several actors — what the Rust
// suite got from reusing one pool across support::app::start calls.
type world struct {
	registry *secretsservice.Registry
	access   *accessservice.Service
	auditLog *fakeAuditRepo
	audit    *auditservice.Service
	tokens   *tokensservice.Service
	identity *identityservice.Service
	codec    *Codec
}

func newWorld(t *testing.T) *world {
	t.Helper()
	registry, err := secretsservice.NewRegistry([]*secretsservice.Store{
		secretsservice.NewStore(config.StoreConfig{
			ID:    "local",
			Kind:  config.KindKeyway,
			Title: "The local vault",
			Allow: []config.Verb{config.Read, config.Edit, config.Create, config.Delete},
		}, newFakeManager("local"), nil),
	})
	require.NoError(t, err)
	codec, err := NewCodec(GenerateKey())
	require.NoError(t, err)
	auditLog := &fakeAuditRepo{}
	return &world{
		registry: registry,
		access:   accessservice.NewService(newFakeAccessRepo()),
		auditLog: auditLog,
		audit:    auditservice.NewService(auditLog),
		tokens:   tokensservice.NewService(newFakeTokenRepo()),
		identity: identityservice.NewService(&fakeIdentityRepo{}, nil),
		codec:    codec,
	}
}

// serverAs starts a listener over the shared world, acting as one person —
// the Rust support::app::start.
func (w *world) serverAs(
	t *testing.T, handle identityentity.Handle,
	roles []identityentity.Role, groups []identityentity.GroupName,
) *httptest.Server {
	t.Helper()
	state := &State{
		Stores:   w.registry,
		Access:   w.access,
		Audit:    w.audit,
		Tokens:   w.tokens,
		Identity: w.identity,
		Auth: &Auth{
			Tokens:   w.tokens,
			Identity: w.identity,
			Dev:      &identityservice.DevActor{Handle: handle, Roles: roles, Groups: groups},
			Codec:    w.codec,
		},
		Branding:     config.Branding{Name: "keyway", Accent: "#2563eb"},
		SessionHours: 8,
		Codec:        w.codec,
	}
	server := httptest.NewServer(Build(state))
	t.Cleanup(server.Close)
	return server
}

// seed creates a secret through the API and returns its uuid, like the Rust
// suite's seed().
func seed(t *testing.T, server *httptest.Server, name, value string) string {
	t.Helper()
	var created map[string]any
	response := postJSON(t, server.Client(), server.URL+"/api/secrets", map[string]any{
		"store": "local", "name": name, "value": value,
	}, &created)
	require.Equal(t, http.StatusOK, response.StatusCode)
	id, ok := created["id"].(string)
	require.True(t, ok, "an id")
	return id
}

func bodyOf(t *testing.T, response *http.Response) string {
	t.Helper()
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return buffer.String()
}

// ---- the External Secrets contract ----------------------------------------
//
// The shape other people's clusters depend on: breaking it breaks reconcile
// loops rather than a screen.

func TestEsoReadsAWholeKvSecretAsFlatJSON(t *testing.T) {
	t.Parallel()
	alice := newWorld(t).serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db", `{"db_password":"hunter2","api_key":"abc"}`)

	response, err := alice.Client().Get(alice.URL + "/api/secrets/" + id + "/value")
	require.NoError(t, err)
	body := bodyOf(t, response)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.JSONEq(t, `{"db_password":"hunter2","api_key":"abc"}`, body, "flat json")
}

func TestEsoReadsOnePropertyAsARawValue(t *testing.T) {
	// Raw, not JSON-quoted — a quoted value would land in the Kubernetes
	// Secret with the quotes in it.
	t.Parallel()
	alice := newWorld(t).serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db", `{"db_password":"hunter2"}`)

	response, err := alice.Client().Get(alice.URL + "/api/secrets/" + id + "/value?key=db_password")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", bodyOf(t, response), "no quotes, no whitespace, no newline")
}

func TestEsoReadsATextSecretVerbatim(t *testing.T) {
	t.Parallel()
	alice := newWorld(t).serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "token", "not-json-at-all")

	response, err := alice.Client().Get(alice.URL + "/api/secrets/" + id + "/value")
	require.NoError(t, err)
	assert.Equal(t, "not-json-at-all", bodyOf(t, response))
}

func TestARevealByKeyOfANonObjectJSONPayloadIsNotFound(t *testing.T) {
	// Valid JSON with no keys to index: the Rust Value::get answered None,
	// which reported as 404 — never 400, never a 200 with garbage.
	t.Parallel()
	alice := newWorld(t).serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "list", `["a","b"]`)

	response, err := alice.Client().Get(alice.URL + "/api/secrets/" + id + "/value?key=x")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
}

// ---- what one caller sees of another's secrets -----------------------------

func TestASecretNobodyGrantedIsNotFoundRatherThanForbidden(t *testing.T) {
	// A distinguishable answer would let anyone enumerate the inventory.
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	mallory := deployment.serverAs(t, "mallory", nil, nil)
	response, err := mallory.Client().Get(mallory.URL + "/api/secrets/" + id)
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
}

func TestAListingShowsOnlyWhatTheCallerCanSee(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	seed(t, alice, "db-creds", "hunter2")

	mallory := deployment.serverAs(t, "mallory", nil, nil)
	var listed []map[string]any
	getJSON(t, mallory.Client(), mallory.URL+"/api/secrets", &listed)
	assert.Empty(t, listed)

	var mine []map[string]any
	getJSON(t, alice.Client(), alice.URL+"/api/secrets", &mine)
	assert.Len(t, mine, 1)
}

// ---- delegations over the wire ---------------------------------------------

func TestAGroupGrantReachesAMemberOverHTTP(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", `{"db_password":"hunter2"}`)

	response := postJSON(t, alice.Client(), alice.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "group", "subject": "SRE", "level": "read", "keys": []string{"db_password"},
	}, nil)
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Bob is in SRE and holds no roles at all: the grant alone opens it.
	bob := deployment.serverAs(t, "bob", nil, []identityentity.GroupName{"SRE"})
	value, err := bob.Client().Get(bob.URL + "/api/secrets/" + id + "/value?key=db_password")
	require.NoError(t, err)
	body := bodyOf(t, value)
	assert.Equal(t, http.StatusOK, value.StatusCode)
	assert.Equal(t, "hunter2", body)
}

func TestADelegatedBasisCarriesTheRustWireString(t *testing.T) {
	// The flagged probe: an exotic subject — uppercase, a space — reads back
	// as the Rust Debug rendering, lowercased whole. The dashboard prints
	// this string verbatim, so it is the wire contract, oddity and all.
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "shared", "hunter2")

	response := postJSON(t, alice.Client(), alice.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "group", "subject": "SRE Team", "level": "guest",
	}, nil)
	require.Equal(t, http.StatusOK, response.StatusCode)

	bob := deployment.serverAs(t, "bob", nil, []identityentity.GroupName{"SRE Team"})
	var seen map[string]any
	getJSON(t, bob.Client(), bob.URL+"/api/secrets/"+id, &seen)
	assert.Equal(t, `delegated { subject: "sre team" }`, seen["basis"])
	assert.Equal(t, "guest", seen["level"])
}

func TestAKeyScopedGrantOpensOnlyThatKeyOverHTTP(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "bot-creds", `{"db_password":"hunter2","api_key":"abc"}`)

	response := postJSON(t, alice.Client(), alice.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "group", "subject": "SRE", "level": "read", "keys": []string{"db_password"},
	}, nil)
	require.Equal(t, http.StatusOK, response.StatusCode)

	bob := deployment.serverAs(t, "bob", nil, []identityentity.GroupName{"SRE"})
	granted, err := bob.Client().Get(bob.URL + "/api/secrets/" + id + "/value?key=db_password")
	require.NoError(t, err)
	_ = granted.Body.Close()
	assert.Equal(t, http.StatusOK, granted.StatusCode)

	// What makes it safe to bundle a bot's credentials into one secret.
	withheld, err := bob.Client().Get(bob.URL + "/api/secrets/" + id + "/value?key=api_key")
	require.NoError(t, err)
	_ = withheld.Body.Close()
	assert.Equal(t, http.StatusForbidden, withheld.StatusCode)
}

func TestAReadGrantDoesNotPermitANewVersionOverHTTP(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	postJSON(t, alice.Client(), alice.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "user", "subject": "bob", "level": "read",
	}, nil)

	bob := deployment.serverAs(t, "bob", nil, nil)
	patched := postJSON(t, bob.Client(), bob.URL+"/api/secrets/"+id+"/versions",
		map[string]any{"value": "hunter3"}, nil)
	assert.Equal(t, http.StatusForbidden, patched.StatusCode)
}

func TestAGranteeAtWriteStillCannotDeleteOrReDelegate(t *testing.T) {
	// Ownership, not level, carries the right to destroy or hand on.
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	postJSON(t, alice.Client(), alice.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "user", "subject": "bob", "level": "write",
	}, nil)

	bob := deployment.serverAs(t, "bob", nil, nil)

	pushed := postJSON(t, bob.Client(), bob.URL+"/api/secrets/"+id+"/versions",
		map[string]any{"value": "hunter3"}, nil)
	assert.Equal(t, http.StatusOK, pushed.StatusCode, "write may push a version")

	request, err := http.NewRequest(http.MethodDelete, bob.URL+"/api/secrets/"+id, nil)
	require.NoError(t, err)
	deleted, err := bob.Client().Do(request)
	require.NoError(t, err)
	_ = deleted.Body.Close()
	assert.Equal(t, http.StatusForbidden, deleted.StatusCode, "write is not the power to destroy")

	redelegated := postJSON(t, bob.Client(), bob.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "user", "subject": "mallory", "level": "read",
	}, nil)
	assert.Equal(t, http.StatusForbidden, redelegated.StatusCode, "a grantee cannot re-delegate")
}

// ---- the audit trail -------------------------------------------------------

func TestATokenActsAsItsHolderAndIsNamedInTheAuditRow(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	response := postJSON(t, alice.Client(), alice.URL+"/api/tokens",
		map[string]any{"name": "eso prod"}, &minted)
	require.Equal(t, http.StatusCreated, response.StatusCode)

	request, err := http.NewRequest(http.MethodGet, alice.URL+"/api/secrets/"+id+"/value", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+minted.Token)
	value, err := alice.Client().Do(request)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", bodyOf(t, value))

	// The reveal names WHICH credential acted, not merely which account.
	deployment.auditLog.mu.Lock()
	defer deployment.auditLog.mu.Unlock()
	var lastReveal *auditentity.Entry
	for i := range deployment.auditLog.entries {
		if deployment.auditLog.entries[i].Action == auditentity.Reveal {
			lastReveal = &deployment.auditLog.entries[i]
		}
	}
	require.NotNil(t, lastReveal, "the reveal was audited")
	assert.Equal(t, "alice", lastReveal.Actor)
	assert.Equal(t, minted.ID, lastReveal.ViaToken)
}

func TestViewingDoesNotWriteAReveal(t *testing.T) {
	// Browsing must never fill the audit log with reveals nobody performed.
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	response, err := alice.Client().Get(alice.URL + "/api/secrets/" + id)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	deployment.auditLog.mu.Lock()
	defer deployment.auditLog.mu.Unlock()
	for _, entry := range deployment.auditLog.entries {
		assert.NotEqual(t, auditentity.Reveal, entry.Action)
	}
}

// ---- malformed bodies ------------------------------------------------------

// TestMalformedBodiesAnswerTheAxumStatuses pins the split axum's Json
// extractor gave every POST route: a missing or wrong Content-Type is 415,
// JSON that does not parse is 400, and JSON that parses but does not fit the
// shape — wrong type, null, missing required field — is 422.
func TestMalformedBodiesAnswerTheAxumStatuses(t *testing.T) {
	t.Parallel()
	deployment := newWorld(t)
	alice := deployment.serverAs(t, "alice", []identityentity.Role{identityentity.RoleCreate}, nil)
	id := seed(t, alice, "db-creds", "hunter2")

	routes := map[string]string{
		"create":   "/api/secrets",
		"patch":    "/api/secrets/" + id + "/versions",
		"delegate": "/api/secrets/" + id + "/grants",
		"mint":     "/api/tokens",
	}
	// Wrong-shape bodies per route: a wrong type, a null required field, and
	// a missing required field. All three parse as JSON, none fits.
	wrongShape := map[string][]string{
		"create": {
			`{"store": 5, "name": "x", "value": "y"}`,
			`{"store": null, "name": "x", "value": "y"}`,
			`{"name": "x", "value": "y"}`,
		},
		"patch": {
			`{"value": 5}`,
			`{"value": null}`,
			`{}`,
		},
		"delegate": {
			`{"subject_kind": 5, "subject": "bob", "level": "read"}`,
			`{"subject_kind": null, "subject": "bob", "level": "read"}`,
			`{"subject": "bob", "level": "read"}`,
		},
		"mint": {
			`{"name": 5}`,
			`{"name": null}`,
			`{}`,
		},
	}

	post := func(t *testing.T, url, contentType, body string) int {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		require.NoError(t, err)
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		response, err := alice.Client().Do(request)
		require.NoError(t, err)
		_ = response.Body.Close()
		return response.StatusCode
	}

	for name, path := range routes {
		t.Run(name, func(t *testing.T) {
			url := alice.URL + path

			assert.Equal(t, http.StatusUnsupportedMediaType, post(t, url, "", `{}`),
				"no Content-Type is 415")
			assert.Equal(t, http.StatusUnsupportedMediaType, post(t, url, "text/plain", `{}`),
				"a wrong Content-Type is 415")
			assert.Equal(t, http.StatusBadRequest, post(t, url, "application/json", `{"broken`),
				"JSON that does not parse is 400")
			for _, body := range wrongShape[name] {
				assert.Equal(t, http.StatusUnprocessableEntity,
					post(t, url, "application/json", body),
					"JSON of the wrong shape is 422: %s", body)
			}
		})
	}
}
