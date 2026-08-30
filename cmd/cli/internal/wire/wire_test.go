package wire

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/cmd/cli/internal/profile"
)

// seen is what one request looked like from the server's side.
type seen struct {
	method string
	path   string
	query  string
	auth   string
	body   []byte
}

// serve records every request and answers each with the given status and body.
func serve(t *testing.T, status int, body string) (*Client, *[]seen) {
	t.Helper()
	var requests []seen
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		requests = append(requests, seen{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			auth:   r.Header.Get("Authorization"),
			body:   payload,
		})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	// The trailing slash proves the client trims before joining paths.
	client := NewClient(profile.Profile{URL: server.URL + "/", Token: "kw-test"})
	return client, &requests
}

func str(s string) *string { return &s }

func TestListSpeaksBearerToTheSecretsEndpoint(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK,
		`[{"id":"aaaa","store":"prod","name":"db"}]`)

	secrets, err := client.List(context.Background())
	require.NoError(t, err)

	require.Len(t, *requests, 1)
	request := (*requests)[0]
	assert.Equal(t, http.MethodGet, request.method)
	assert.Equal(t, "/api/secrets", request.path)
	assert.Equal(t, "Bearer kw-test", request.auth)

	require.Len(t, secrets, 1)
	assert.Equal(t, "aaaa", secrets[0].ID)
	assert.Equal(t, "", secrets[0].LatestVersion, "absent fields default rather than fail")
	assert.Nil(t, secrets[0].Level)
}

func TestViewAddressesOneSecret(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK,
		`{"id":"aaaa","store":"prod","name":"db","latest_version":"v2","level":"read","basis":"grant"}`)

	secret, err := client.View(context.Background(), "aaaa")
	require.NoError(t, err)

	assert.Equal(t, "/api/secrets/aaaa", (*requests)[0].path)
	assert.Equal(t, "v2", secret.LatestVersion)
	require.NotNil(t, secret.Level)
	assert.Equal(t, "read", *secret.Level)
	assert.Equal(t, "grant", secret.Basis)
}

func TestRevealReturnsTheBodyVerbatim(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK, "hunter2")

	value, err := client.Reveal(context.Background(), "aaaa", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", value, "a value is not JSON; it is the value")
	assert.Equal(t, "/api/secrets/aaaa/value", (*requests)[0].path)
	assert.Equal(t, "", (*requests)[0].query)
}

func TestRevealBuildsTheQueryFromWhatWasAsked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		key     *string
		version *string
		query   string
	}{
		{"key only", str("db_password"), nil, "key=db_password"},
		{"version only", nil, str("v3"), "version=v3"},
		{"both", str("db_password"), str("v3"), "key=db_password&version=v3"},
		{"empty key still asked", str(""), nil, "key="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, requests := serve(t, http.StatusOK, "x")
			_, err := client.Reveal(context.Background(), "aaaa", tc.key, tc.version)
			require.NoError(t, err)
			assert.Equal(t, tc.query, (*requests)[0].query)
		})
	}
}

func TestCreatePostsTheFourFields(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK, `{"id":"aaaa","store":"prod","name":"db"}`)

	secret, err := client.Create(context.Background(), "prod", "db", "hunter2", "a note")
	require.NoError(t, err)
	assert.Equal(t, "aaaa", secret.ID)

	request := (*requests)[0]
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, "/api/secrets", request.path)
	assert.Equal(t, "Bearer kw-test", request.auth)
	assert.JSONEq(t,
		`{"store":"prod","name":"db","value":"hunter2","note":"a note"}`,
		string(request.body))
}

func TestPatchPostsANewVersion(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK, `{"id":"v4","state":"active"}`)

	version, err := client.Patch(context.Background(), "aaaa", "hunter3", "")
	require.NoError(t, err)
	assert.Equal(t, "v4", version.ID)
	assert.Equal(t, "active", version.State)

	request := (*requests)[0]
	assert.Equal(t, "/api/secrets/aaaa/versions", request.path)
	assert.JSONEq(t, `{"value":"hunter3","note":""}`, string(request.body))
}

func TestDelegatePostsTheGrantWithEmptyKeysAsAList(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK,
		`{"id":"g1","subject_kind":"user","subject":"sam","level":"read","granted_by":"ana"}`)

	grant, err := client.Delegate(context.Background(), "aaaa", NewGrant{
		Kind: "user", Subject: "sam", Level: "read", Days: 7, Note: "on call",
	})
	require.NoError(t, err)

	request := (*requests)[0]
	assert.Equal(t, "/api/secrets/aaaa/grants", request.path)
	assert.JSONEq(t,
		`{"subject_kind":"user","subject":"sam","level":"read","keys":[],"days":7,"note":"on call"}`,
		string(request.body))
	// And literally `[]`, never `null`: no keys means an unrestricted grant,
	// not an absent field.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(request.body, &raw))
	assert.Equal(t, "[]", string(raw["keys"]))

	assert.NotNil(t, grant.Keys, "the answer's missing keys default to empty")
	assert.Empty(t, grant.Keys)
}

func TestDelegateSendsTheKeysItWasGiven(t *testing.T) {
	t.Parallel()
	client, requests := serve(t, http.StatusOK,
		`{"id":"g1","subject_kind":"group","subject":"sre","level":"write","keys":["a","b"],"granted_by":"ana"}`)

	grant, err := client.Delegate(context.Background(), "aaaa", NewGrant{
		Kind: "group", Subject: "sre", Level: "write", Keys: []string{"a", "b"},
	})
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"subject_kind":"group","subject":"sre","level":"write","keys":["a","b"],"days":0,"note":""}`,
		string((*requests)[0].body))
	assert.Equal(t, []string{"a", "b"}, grant.Keys)
}

func TestAFailureBecomesASentence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		body    string
		message string
	}{
		{
			"401 has one meaning regardless of the body",
			http.StatusUnauthorized, `{"error":"token expired"}`,
			"not signed in, or the token is no longer valid",
		},
		{
			"403 repeats what the server said",
			http.StatusForbidden, `{"error":"read is not write"}`,
			"read is not write",
		},
		{
			"404 will not distinguish absent from invisible",
			http.StatusNotFound, `{"error":"not found"}`,
			"no such secret, or you cannot see it",
		},
		{
			"anything else quotes status and message",
			http.StatusInternalServerError, `{"error":"the database is on fire"}`,
			"keyway said 500 Internal Server Error: the database is on fire",
		},
		{
			"a body that is not an API error passes through as-is",
			http.StatusBadGateway, "upstream gone",
			"keyway said 502 Bad Gateway: upstream gone",
		},
		{
			"JSON without an error field is not mistaken for one",
			http.StatusBadGateway, `{"detail":"nope"}`,
			`keyway said 502 Bad Gateway: {"detail":"nope"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, _ := serve(t, tc.status, tc.body)
			_, err := client.List(context.Background())
			require.Error(t, err)
			assert.Equal(t, tc.message, err.Error())
		})
	}
}

func TestAnUnreachableServerMentionsReachingKeyway(t *testing.T) {
	t.Parallel()
	client := NewClient(profile.Profile{URL: "http://127.0.0.1:1", Token: "kw-test"})
	_, err := client.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reaching keyway")
}
