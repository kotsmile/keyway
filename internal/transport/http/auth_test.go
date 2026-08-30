package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
	tokensentity "github.com/kotsmile/keyway/internal/tokens/entity"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
)

// stubTokenRepo is tokens storage in a map — the auth branching under test
// lives above the repository, so the repository can be trivial.
type stubTokenRepo struct {
	mu     sync.Mutex
	stored map[string]tokensentity.StoredToken
}

func newStubTokenRepo() *stubTokenRepo {
	return &stubTokenRepo{stored: map[string]tokensentity.StoredToken{}}
}

func (r *stubTokenRepo) Insert(_ context.Context, token tokensentity.StoredToken) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token.CreatedAt = time.Now()
	r.stored[token.ID] = token
	return token.CreatedAt, nil
}

func (r *stubTokenRepo) ByID(_ context.Context, id string) (*tokensentity.StoredToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.stored[id]
	if !ok {
		return nil, nil
	}
	return &token, nil
}

func (r *stubTokenRepo) ForSubject(_ context.Context, subject string) ([]tokensentity.Token, error) {
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

func (r *stubTokenRepo) Delete(_ context.Context, subject, id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.stored[id]
	if !ok || stored.Subject != subject {
		return false, nil
	}
	delete(r.stored, id)
	return true, nil
}

func (r *stubTokenRepo) Touch(_ context.Context, _ string, _ time.Time) {}

// stubIdentityRepo remembers sign-ins in a map.
type stubIdentityRepo struct {
	mu    sync.Mutex
	users map[string]identityentity.RememberedUser
}

func newStubIdentityRepo() *stubIdentityRepo {
	return &stubIdentityRepo{users: map[string]identityentity.RememberedUser{}}
}

func (r *stubIdentityRepo) Remember(_ context.Context, user *identityentity.RememberedUser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.Handle] = *user
	return nil
}

func (r *stubIdentityRepo) Recall(_ context.Context, handle string) (*identityentity.RememberedUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[handle]
	if !ok {
		return nil, nil
	}
	return &user, nil
}

// authUnderTest is an Auth over in-memory services, with the clock held
// still.
func authUnderTest(t *testing.T, dev *DevActor) (*Auth, *tokensservice.Service, *stubIdentityRepo) {
	t.Helper()
	tokenService := tokensservice.NewService(newStubTokenRepo())
	users := newStubIdentityRepo()
	return &Auth{
		Tokens:   tokenService,
		Identity: identityservice.NewService(users, nil),
		Dev:      dev,
		Codec:    testCodec(t),
		Now:      time.Now,
	}, tokenService, users
}

func TestABearerTokenActsAsThePersonWhoMintedIt(t *testing.T) {
	t.Parallel()
	auth, tokenService, users := authUnderTest(t, nil)
	ctx := context.Background()

	// alice signed in once; her groups were remembered (ADR-0004).
	require.NoError(t, users.Remember(ctx, &identityentity.RememberedUser{
		Handle: "alice", Groups: []string{"SRE"},
	}))
	minted, err := tokenService.Mint(ctx, "alice", "ci", nil)
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.Header.Set("Authorization", "Bearer "+minted.Plaintext)

	actor, err := auth.Resolve(request)
	require.NoError(t, err)
	assert.Equal(t, "alice", actor.Handle())
	assert.Contains(t, actor.GroupNames(), "SRE",
		"a token carries its holder's remembered groups")
	tokenID, viaToken := actor.TokenID()
	assert.True(t, viaToken, "the audit line must say which token acted")
	assert.Equal(t, minted.Token.ID, tokenID)
	assert.False(t, actor.IsAdmin(), "a token carries no roles of its own")
}

func TestEveryTokenRejectionAnswersTheSame401(t *testing.T) {
	t.Parallel()
	auth, tokenService, _ := authUnderTest(t, nil)
	minted, err := tokenService.Mint(context.Background(), "alice", "ci", nil)
	require.NoError(t, err)

	// Malformed, unknown id, wrong secret: which one it was goes to the log,
	// never to the wire — "that id exists but the secret is wrong" is a fact
	// worth guessing for.
	for name, presented := range map[string]string{
		"malformed":    "not-a-token",
		"unknown id":   "kw-ffffffffffffffff-ffffffffffffffffffffffffffffffff",
		"wrong secret": minted.Plaintext + "x",
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		request.Header.Set("Authorization", "Bearer "+presented)
		_, err := auth.Resolve(request)
		var api *ApiError
		require.ErrorAs(t, err, &api, name)
		assert.Equal(t, http.StatusUnauthorized, api.Status, name)
		assert.Equal(t, "unauthorized", api.Message, name)
	}
}

func TestALiveSessionCookieResolvesItsActor(t *testing.T) {
	t.Parallel()
	auth, _, _ := authUnderTest(t, nil)
	cookie, err := session(time.Now().Add(time.Hour)).Cookie(auth.Codec, 1)
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.AddCookie(cookie)

	actor, err := auth.Resolve(request)
	require.NoError(t, err)
	assert.Equal(t, "alice", actor.Handle())
	assert.True(t, actor.MayCreate())
	_, viaToken := actor.TokenID()
	assert.False(t, viaToken, "a browser session is not a token")
}

func TestAnExpiredSessionIsRefusedNotIgnored(t *testing.T) {
	t.Parallel()
	// Expired rather than absent: saying so is what lets the console send
	// somebody back to sign in instead of showing an empty page. It also must
	// NOT fall through to the dev actor.
	auth, _, _ := authUnderTest(t, &DevActor{Handle: "dev"})
	cookie, err := session(time.Now().Add(-time.Minute)).Cookie(auth.Codec, 1)
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.AddCookie(cookie)

	_, err = auth.Resolve(request)
	var api *ApiError
	require.ErrorAs(t, err, &api)
	assert.Equal(t, http.StatusUnauthorized, api.Status)
}

func TestNoCredentialInDevModeIsTheConfiguredUser(t *testing.T) {
	t.Parallel()
	auth, _, _ := authUnderTest(t, &DevActor{
		Handle: "dev",
		Roles:  []identityentity.Role{identityentity.RoleAdmin, identityentity.RoleCreate},
		Groups: []string{"local"},
	})

	actor, err := auth.Resolve(httptest.NewRequest(http.MethodGet, "/api/me", nil))
	require.NoError(t, err)
	assert.Equal(t, "dev", actor.Handle())
	assert.True(t, actor.IsAdmin(),
		"dev mode still makes every authz decision; the dev user simply holds the roles")
}

func TestNoCredentialOutsideDevModeIsNobody(t *testing.T) {
	t.Parallel()
	auth, _, _ := authUnderTest(t, nil)
	_, err := auth.Resolve(httptest.NewRequest(http.MethodGet, "/api/me", nil))
	var api *ApiError
	require.ErrorAs(t, err, &api)
	assert.Equal(t, http.StatusUnauthorized, api.Status)
}

func TestABearerHeaderWinsOverACookie(t *testing.T) {
	t.Parallel()
	// The Rust extractor tried the doors in this order; the CLI may run on a
	// machine whose browser also holds a session, and the credential the
	// caller presented explicitly is the one that should act.
	auth, tokenService, _ := authUnderTest(t, nil)
	minted, err := tokenService.Mint(context.Background(), "bob", "cli", nil)
	require.NoError(t, err)
	cookie, err := session(time.Now().Add(time.Hour)).Cookie(auth.Codec, 1)
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.AddCookie(cookie)
	request.Header.Set("Authorization", "Bearer "+minted.Plaintext)

	actor, err := auth.Resolve(request)
	require.NoError(t, err)
	assert.Equal(t, "bob", actor.Handle())
}

func TestMiddlewareCarriesTheActorToTheHandler(t *testing.T) {
	t.Parallel()
	auth, _, _ := authUnderTest(t, &DevActor{Handle: "dev"})

	var seen identityentity.Actor
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = Caller(r.Context())
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/me", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "dev", seen.Handle())
}

func TestMiddlewareRefusesBeforeTheHandlerRuns(t *testing.T) {
	t.Parallel()
	auth, _, _ := authUnderTest(t, nil)

	reached := false
	handler := auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/me", nil))

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.False(t, reached, "an unauthenticated request must not reach a handler")
}
