package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/config"
	accessentity "github.com/kotsmile/keyway/internal/access/entity"
	accessservice "github.com/kotsmile/keyway/internal/access/service"
	auditentity "github.com/kotsmile/keyway/internal/audit/entity"
	auditservice "github.com/kotsmile/keyway/internal/audit/service"
	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
	"github.com/kotsmile/keyway/internal/telemetry"
	tokensentity "github.com/kotsmile/keyway/internal/tokens/entity"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
)

// ---- in-memory fakes -------------------------------------------------------
//
// The routes under test are the wire contract; the domains below them are
// already tested against a real database. So every port gets the smallest
// fake that keeps the real services running.

// fakeManager is a SecretManager over a map — the "fake SecretManager" the
// secrets happy path runs against.
type fakeManager struct {
	mu      sync.Mutex
	store   secretsentity.StoreID
	secrets map[secretsentity.SecretName]*fakeSecret
}

type fakeSecret struct {
	labels   secretsentity.Metadata
	payloads [][]byte
}

func newFakeManager(store secretsentity.StoreID) *fakeManager {
	return &fakeManager{store: store, secrets: map[secretsentity.SecretName]*fakeSecret{}}
}

func (m *fakeManager) List(context.Context) ([]secretsentity.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []secretsentity.Secret{}
	for name := range m.secrets {
		out = append(out, m.snapshot(name))
	}
	return out, nil
}

func (m *fakeManager) Get(_ context.Context, name secretsentity.SecretName) (secretsentity.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[name]; !ok {
		return secretsentity.Secret{}, secretsentity.ErrNotFound
	}
	return m.snapshot(name), nil
}

func (m *fakeManager) snapshot(name secretsentity.SecretName) secretsentity.Secret {
	held := m.secrets[name]
	var latest secretsentity.VersionID
	if n := len(held.payloads); n > 0 {
		latest = secretsentity.VersionID(strconv.Itoa(n))
	}
	return secretsentity.Secret{
		Store: m.store, Name: name, Labels: held.labels, LatestVersion: latest,
	}
}

func (m *fakeManager) Versions(_ context.Context, name secretsentity.SecretName) ([]secretsentity.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.secrets[name]
	if !ok {
		return nil, secretsentity.ErrNotFound
	}
	out := []secretsentity.Version{}
	for i := len(held.payloads); i > 0; i-- {
		out = append(out, secretsentity.Version{
			ID: secretsentity.VersionID(strconv.Itoa(i)), State: secretsentity.VersionEnabled,
		})
	}
	return out, nil
}

func (m *fakeManager) Access(
	_ context.Context, name secretsentity.SecretName, version secretsentity.VersionID,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.secrets[name]
	if !ok {
		return nil, secretsentity.ErrNotFound
	}
	if version.IsLatest() {
		version = secretsentity.VersionID(strconv.Itoa(len(held.payloads)))
	}
	number, err := strconv.Atoi(version.String())
	if err != nil || number < 1 || number > len(held.payloads) {
		return nil, &secretsentity.NoSuchVersionError{Version: version}
	}
	return held.payloads[number-1], nil
}

func (m *fakeManager) SetLabels(_ context.Context, name secretsentity.SecretName, labels secretsentity.Metadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.secrets[name]
	if !ok {
		return secretsentity.ErrNotFound
	}
	held.labels = labels
	return nil
}

func (m *fakeManager) Create(_ context.Context, name secretsentity.SecretName, labels secretsentity.Metadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[name] = &fakeSecret{labels: labels}
	return nil
}

func (m *fakeManager) AddVersion(_ context.Context, name secretsentity.SecretName, payload []byte) (secretsentity.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.secrets[name]
	if !ok {
		return secretsentity.Version{}, secretsentity.ErrNotFound
	}
	held.payloads = append(held.payloads, payload)
	return secretsentity.Version{
		ID: secretsentity.VersionID(strconv.Itoa(len(held.payloads))), State: secretsentity.VersionEnabled,
	}, nil
}

func (m *fakeManager) Delete(_ context.Context, name secretsentity.SecretName) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[name]; !ok {
		return secretsentity.ErrNotFound
	}
	delete(m.secrets, name)
	return nil
}

// fakeAccessRepo keeps owners and grants in maps.
type fakeAccessRepo struct {
	mu     sync.Mutex
	owners map[string]accessentity.Ownership
	grants map[uuid.UUID]accessentity.Delegation
}

func newFakeAccessRepo() *fakeAccessRepo {
	return &fakeAccessRepo{
		owners: map[string]accessentity.Ownership{},
		grants: map[uuid.UUID]accessentity.Delegation{},
	}
}

func onKey(store secretsentity.StoreID, secret secretsentity.SecretName) string {
	return store.String() + "\x00" + secret.String()
}

func (r *fakeAccessRepo) GrantsOn(
	_ context.Context, store secretsentity.StoreID, secret secretsentity.SecretName,
) ([]accessentity.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []accessentity.Delegation{}
	for _, grant := range r.grants {
		if grant.Store == store && grant.Secret == secret {
			out = append(out, grant)
		}
	}
	return out, nil
}

func (r *fakeAccessRepo) OwnerOf(
	_ context.Context, store secretsentity.StoreID, secret secretsentity.SecretName,
) (*accessentity.Ownership, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.owners[onKey(store, secret)]
	if !ok {
		return nil, nil
	}
	return &owner, nil
}

func (r *fakeAccessRepo) GrantsForSubjects(_ context.Context, subjects []accessentity.Subject) ([]accessentity.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []accessentity.Delegation{}
	for _, grant := range r.grants {
		for _, subject := range subjects {
			if grant.Subject == subject {
				out = append(out, grant)
			}
		}
	}
	return out, nil
}

func (r *fakeAccessRepo) SaveGrant(_ context.Context, grant accessentity.Delegation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grants[grant.ID] = grant
	return nil
}

func (r *fakeAccessRepo) RemoveGrant(_ context.Context, id uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.grants[id]; !ok {
		return false, nil
	}
	delete(r.grants, id)
	return true, nil
}

func (r *fakeAccessRepo) SetOwner(_ context.Context, ownership accessentity.Ownership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.owners[onKey(ownership.Store, ownership.Secret)] = ownership
	return nil
}

// fakeAuditRepo appends to a slice, newest first on read, the way the real
// feed reads back.
type fakeAuditRepo struct {
	mu      sync.Mutex
	entries []auditentity.Entry
}

func (r *fakeAuditRepo) Append(_ context.Context, actor, viaToken string, record auditentity.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := record.SecretID
	r.entries = append(r.entries, auditentity.Entry{
		ID:       int64(len(r.entries) + 1),
		At:       time.Now(),
		Actor:    actor,
		ViaToken: viaToken,
		Action:   record.Action,
		Store:    record.Store,
		Secret:   record.Secret,
		SecretID: &id,
		Version:  record.Version,
		Keys:     record.Keys,
		Subject:  record.Subject,
		Note:     record.Note,
	})
	return nil
}

func (r *fakeAuditRepo) ForSecret(
	_ context.Context, store secretsentity.StoreID, secret secretsentity.SecretName, _ int64,
) ([]auditentity.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []auditentity.Entry{}
	for i := len(r.entries) - 1; i >= 0; i-- {
		if r.entries[i].Store == store && r.entries[i].Secret == secret {
			out = append(out, r.entries[i])
		}
	}
	return out, nil
}

func (r *fakeAuditRepo) Feed(_ context.Context, limit int64, _ *int64) ([]auditentity.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []auditentity.Entry{}
	for i := len(r.entries) - 1; i >= 0 && int64(len(out)) < limit; i-- {
		out = append(out, r.entries[i])
	}
	return out, nil
}

// fakeTokenRepo is tokens storage in a map.
type fakeTokenRepo struct {
	mu     sync.Mutex
	stored map[tokensentity.ID]tokensentity.StoredToken
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{stored: map[tokensentity.ID]tokensentity.StoredToken{}}
}

func (r *fakeTokenRepo) Insert(_ context.Context, token tokensentity.StoredToken) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token.CreatedAt = time.Now()
	r.stored[token.ID] = token
	return token.CreatedAt, nil
}

func (r *fakeTokenRepo) ByID(_ context.Context, id tokensentity.ID) (*tokensentity.StoredToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.stored[id]
	if !ok {
		return nil, nil
	}
	return &token, nil
}

func (r *fakeTokenRepo) ForSubject(_ context.Context, subject string) ([]tokensentity.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []tokensentity.Token{}
	for _, stored := range r.stored {
		if stored.Subject == subject {
			out = append(out, tokensentity.Token{
				ID: stored.ID, Subject: stored.Subject, Name: stored.Name,
				CreatedAt: stored.CreatedAt, ExpiresAt: stored.ExpiresAt, LastUsed: stored.LastUsed,
			})
		}
	}
	return out, nil
}

func (r *fakeTokenRepo) Delete(_ context.Context, subject string, id tokensentity.ID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.stored[id]
	if !ok || stored.Subject != subject {
		return false, nil
	}
	delete(r.stored, id)
	return true, nil
}

func (r *fakeTokenRepo) Touch(context.Context, tokensentity.ID, time.Time) {}

// fakeIdentityRepo remembers sign-ins in a map.
type fakeIdentityRepo struct {
	mu    sync.Mutex
	users map[identityentity.Handle]identityentity.RememberedUser
}

func (r *fakeIdentityRepo) Remember(_ context.Context, user *identityentity.RememberedUser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.users == nil {
		r.users = map[identityentity.Handle]identityentity.RememberedUser{}
	}
	r.users[user.Handle] = *user
	return nil
}

func (r *fakeIdentityRepo) Recall(_ context.Context, handle identityentity.Handle) (*identityentity.RememberedUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[handle]
	if !ok {
		return nil, nil
	}
	return &user, nil
}

// ---- the server under test -------------------------------------------------

// serverUnderTest is the whole API router over in-memory fakes, in dev mode
// as `dev` holding the given roles — the same wiring serve() does, minus
// PostgreSQL and the issuer.
func serverUnderTest(t *testing.T, devRoles ...identityentity.Role) *httptest.Server {
	t.Helper()

	registry, err := secretsservice.NewRegistry([]*secretsservice.Store{
		secretsservice.NewStore(config.StoreConfig{
			ID:    "vault",
			Kind:  config.KindKeyway,
			Title: "The test vault",
			Allow: []config.Verb{config.Read, config.Edit, config.Create, config.Delete},
		}, newFakeManager("vault"), nil),
	})
	require.NoError(t, err)

	codec, err := NewCodec(GenerateKey())
	require.NoError(t, err)

	tokenService := tokensservice.NewService(newFakeTokenRepo())
	identityService := identityservice.NewService(&fakeIdentityRepo{}, nil)

	state := &State{
		Stores:   registry,
		Access:   accessservice.NewService(newFakeAccessRepo()),
		Audit:    auditservice.NewService(&fakeAuditRepo{}),
		Tokens:   tokenService,
		Identity: identityService,
		Auth: &Auth{
			Tokens:   tokenService,
			Identity: identityService,
			Dev:      &identityservice.DevActor{Handle: "dev", Roles: devRoles},
			Codec:    codec,
		},
		Branding:     config.Branding{Name: "keyway", Accent: "#2563eb"},
		Oidc:         nil,
		SessionHours: 8,
		Codec:        codec,
	}

	server := httptest.NewServer(Build(state))
	t.Cleanup(server.Close)
	return server
}

func getJSON(t *testing.T, client *http.Client, url string, into any) *http.Response {
	t.Helper()
	response, err := client.Get(url)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	if into != nil {
		require.NoError(t, json.NewDecoder(response.Body).Decode(into))
	}
	return response
}

func postJSON(t *testing.T, client *http.Client, url string, body any, into any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	response, err := client.Post(url, "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	if into != nil {
		require.NoError(t, json.NewDecoder(response.Body).Decode(into))
	}
	return response
}

// ---- the tests -------------------------------------------------------------

func TestHealthzAnswersOkWithNoCredential(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t)

	response, err := http.Get(server.URL + "/healthz")
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	assert.Equal(t, http.StatusOK, response.StatusCode)

	body := make([]byte, 2)
	n, _ := response.Body.Read(body)
	assert.Equal(t, "ok", string(body[:n]))
}

func TestTheMetricsListenerServesScrapesAndHealth(t *testing.T) {
	t.Parallel()
	tel, err := telemetry.Init(context.Background(), "keyway-test", "")
	require.NoError(t, err)
	tel.BackendCall("vault", "list", "ok", 0.01)

	server := httptest.NewServer(Metrics(tel.Handler()))
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/healthz")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)

	response, err = http.Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var scraped bytes.Buffer
	_, err = scraped.ReadFrom(response.Body)
	require.NoError(t, err)
	assert.Contains(t, scraped.String(), "keyway_backend_calls_total",
		"the Rust metric names carry over; the dashboards already exist")
	assert.Contains(t, scraped.String(), "keyway_backend_duration_seconds")
}

func TestMeAnswersTheShapeTheDashboardReads(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t, identityentity.RoleAdmin, identityentity.RoleCreate)

	// Raw JSON rather than a struct: the field names ARE the contract
	// (keyway-dashboard/src/api.ts, interface Me).
	var me map[string]any
	response := getJSON(t, server.Client(), server.URL+"/api/me", &me)
	require.Equal(t, http.StatusOK, response.StatusCode)

	assert.Equal(t, "dev", me["handle"])
	assert.Equal(t, true, me["is_admin"])
	assert.Equal(t, true, me["may_create"])
	assert.Equal(t, false, me["directory"])
	for _, field := range []string{"handle", "groups", "roles", "is_admin", "may_create", "directory", "branding"} {
		assert.Contains(t, me, field)
	}
	branding, ok := me["branding"].(map[string]any)
	require.True(t, ok)
	for _, field := range []string{"name", "logo", "favicon", "accent"} {
		assert.Contains(t, branding, field)
	}
	assert.Equal(t, "keyway", branding["name"])
}

func TestTheSecretsHappyPath(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t, identityentity.RoleCreate)
	client := server.Client()

	// Create.
	var created map[string]any
	response := postJSON(t, client, server.URL+"/api/secrets", map[string]any{
		"store": "vault", "name": "db-password", "value": "hunter2", "note": "the first one",
	}, &created)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "vault", created["store"])
	assert.Equal(t, "db-password", created["name"])
	assert.Equal(t, "owner", created["basis"], "whoever made it owns it")
	assert.Equal(t, "write", created["level"])
	id, ok := created["id"].(string)
	require.True(t, ok, "a secret is addressed by uuid")

	// It shows up in the listing and on the store menu.
	var listed []map[string]any
	getJSON(t, client, server.URL+"/api/secrets", &listed)
	require.Len(t, listed, 1)
	assert.Equal(t, id, listed[0]["id"])

	var stores []map[string]any
	getJSON(t, client, server.URL+"/api/stores", &stores)
	require.Len(t, stores, 1)
	assert.Equal(t, "vault", stores[0]["id"])
	assert.Equal(t, "The test vault", stores[0]["title"])

	// Reveal answers the plaintext, uncacheable.
	response, err := client.Get(server.URL + "/api/secrets/" + id + "/value")
	require.NoError(t, err)
	var value bytes.Buffer
	_, _ = value.ReadFrom(response.Body)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "hunter2", value.String())
	assert.Equal(t, "no-store", response.Header.Get("Cache-Control"),
		"nothing on the way back should keep this")

	// A new version, then the series newest-first.
	var version map[string]any
	response = postJSON(t, client, server.URL+"/api/secrets/"+id+"/versions",
		map[string]any{"value": "hunter3"}, &version)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "2", version["id"])
	assert.Equal(t, "enabled", version["state"])

	var versions []map[string]any
	getJSON(t, client, server.URL+"/api/secrets/"+id+"/versions", &versions)
	require.Len(t, versions, 2)
	assert.Equal(t, "2", versions[0]["id"])

	// Every touch above is in the history, reveal included.
	var history []map[string]any
	getJSON(t, client, server.URL+"/api/secrets/"+id+"/history", &history)
	actions := make([]string, 0, len(history))
	for _, entry := range history {
		actions = append(actions, entry["action"].(string))
		assert.Equal(t, "dev", entry["actor"])
	}
	assert.Equal(t, []string{"update", "reveal", "create"}, actions, "newest first")

	// Delete answers 204 and the listing empties.
	request, err := http.NewRequest(http.MethodDelete, server.URL+"/api/secrets/"+id, nil)
	require.NoError(t, err)
	response, err = client.Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusNoContent, response.StatusCode)

	listed = nil
	getJSON(t, client, server.URL+"/api/secrets", &listed)
	assert.Empty(t, listed)
}

func TestATokenMintedOverHTTPAuthenticatesOverHTTP(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t, identityentity.RoleAdmin)
	client := server.Client()

	var minted struct {
		ID        string  `json:"id"`
		Name      string  `json:"name"`
		Token     string  `json:"token"`
		ExpiresAt *string `json:"expires_at"`
	}
	response := postJSON(t, client, server.URL+"/api/tokens",
		map[string]any{"name": "ci", "days": 30}, &minted)
	require.Equal(t, http.StatusCreated, response.StatusCode)
	assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	assert.Equal(t, "ci", minted.Name)
	assert.NotNil(t, minted.ExpiresAt)
	require.NotEmpty(t, minted.Token)

	// The plaintext now authenticates a request of its own — and the token
	// acts as its holder with no roles, not as the dev actor (ADR-0004).
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/me", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+minted.Token)
	response, err = client.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var me map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&me))
	assert.Equal(t, "dev", me["handle"])
	assert.Equal(t, false, me["is_admin"], "roles are not carried by the token")

	// It lists, and revoking it answers 204; a second revoke is 404.
	var held []map[string]any
	getJSON(t, client, server.URL+"/api/tokens", &held)
	require.Len(t, held, 1)
	assert.Equal(t, minted.ID, held[0]["id"])
	assert.NotContains(t, held[0], "token", "the plaintext exists exactly once")

	for _, wantStatus := range []int{http.StatusNoContent, http.StatusNotFound} {
		request, err = http.NewRequest(http.MethodDelete, server.URL+"/api/tokens/"+minted.ID, nil)
		require.NoError(t, err)
		response, err = client.Do(request)
		require.NoError(t, err)
		_ = response.Body.Close()
		assert.Equal(t, wantStatus, response.StatusCode)
	}
}

func TestARevokedTokenStopsAuthenticating(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t)
	client := server.Client()

	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	postJSON(t, client, server.URL+"/api/tokens", map[string]any{"name": "doomed"}, &minted)

	request, err := http.NewRequest(http.MethodDelete, server.URL+"/api/tokens/"+minted.ID, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusNoContent, response.StatusCode)

	request, err = http.NewRequest(http.MethodGet, server.URL+"/api/me", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+minted.Token)
	response, err = client.Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode,
		"deleting a token is the revocation")
}

func TestTheAuditFeedIsFencedToAdmins(t *testing.T) {
	t.Parallel()
	// The dev actor holds no roles here, so even dev mode is refused: every
	// authorisation decision is still made.
	server := serverUnderTest(t)

	response, err := http.Get(server.URL + "/api/audit")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusForbidden, response.StatusCode)

	admin := serverUnderTest(t, identityentity.RoleAdmin)
	var entries []map[string]any
	response = getJSON(t, admin.Client(), admin.URL+"/api/audit", &entries)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Empty(t, entries)
}

func TestAnUnknownSecretAndABadIdAnswerTheRustStatuses(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t)
	client := server.Client()

	response, err := client.Get(server.URL + "/api/secrets/" + uuid.NewString())
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	response, err = client.Get(server.URL + "/api/secrets/not-a-uuid")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusBadRequest, response.StatusCode, "a name is not an address")
}

func TestCreatingWithoutTheCreateRoleIsForbidden(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t) // no roles
	response := postJSON(t, server.Client(), server.URL+"/api/secrets", map[string]any{
		"store": "vault", "name": "nope", "value": "x",
	}, nil)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
}

func TestGrantsRoundTripOverHTTP(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t, identityentity.RoleCreate)
	client := server.Client()

	var created map[string]any
	postJSON(t, client, server.URL+"/api/secrets", map[string]any{
		"store": "vault", "name": "shared", "value": "s3cret",
	}, &created)
	id := created["id"].(string)

	var grant map[string]any
	response := postJSON(t, client, server.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "user", "subject": "bob", "level": "read", "days": 7, "note": "on call",
	}, &grant)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "user", grant["subject_kind"])
	assert.Equal(t, "bob", grant["subject"])
	assert.Equal(t, "read", grant["level"])
	assert.Equal(t, "dev", grant["granted_by"])
	assert.NotNil(t, grant["expires_at"])

	var grants []map[string]any
	getJSON(t, client, server.URL+"/api/secrets/"+id+"/grants", &grants)
	require.Len(t, grants, 1)

	// An unknown subject_kind is a 400 the caller can fix.
	response = postJSON(t, client, server.URL+"/api/secrets/"+id+"/grants", map[string]any{
		"subject_kind": "team", "subject": "sre", "level": "read",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)

	// Revoke, then the list is empty again.
	request, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/secrets/%s/grants/%s", server.URL, id, grants[0]["id"]), nil)
	require.NoError(t, err)
	response, err = client.Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusNoContent, response.StatusCode)

	grants = nil
	getJSON(t, client, server.URL+"/api/secrets/"+id+"/grants", &grants)
	assert.Empty(t, grants)
}

func TestFailuresAreErrorJSONTheDashboardCanShow(t *testing.T) {
	t.Parallel()
	server := serverUnderTest(t)

	// The dashboard reads `{ error }` from every failure (api.ts request()).
	response := postJSON(t, server.Client(), server.URL+"/api/tokens",
		map[string]any{"name": "x", "days": -1}, nil)
	require.Equal(t, http.StatusBadRequest, response.StatusCode)

	fresh, err := server.Client().Post(server.URL+"/api/tokens", "application/json",
		bytes.NewReader([]byte(`{"name":"x","days":-1}`)))
	require.NoError(t, err)
	defer func() { _ = fresh.Body.Close() }()
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(fresh.Body).Decode(&body))
	assert.Equal(t, "days cannot be negative", body.Error)
}
