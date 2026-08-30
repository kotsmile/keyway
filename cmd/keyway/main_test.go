package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noEnv(string) (string, bool) { return "", false }

func env(pairs map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := pairs[name]
		return value, ok
	}
}

// runCLI runs the command tree exactly as main would, capturing both streams.
func runCLI(t *testing.T, args []string, stdin string, lookupEnv func(string) (string, bool)) (int, string, string) {
	t.Helper()
	var out, errOut strings.Builder
	code := run(args, strings.NewReader(stdin), &out, &errOut, lookupEnv)
	return code, out.String(), errOut.String()
}

// isolate keeps every dialing test away from a real ~/.keyway/config.yml.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

// server answers one canned body and records the requests, echoing the shape
// the Rust CLI spoke against.
func server(t *testing.T, body string, requests *[]*http.Request) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		payload, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		clone.Body = io.NopCloser(strings.NewReader(string(payload)))
		*requests = append(*requests, clone)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestNoCommandIsAUsageError(t *testing.T) {
	code, out, errOut := runCLI(t, nil, "", noEnv)
	assert.Equal(t, 2, code, "clap exits 2 when the subcommand is missing")
	assert.Empty(t, out)
	assert.Contains(t, errOut, "Usage:", "help lands on stderr, not stdout")
}

func TestAnUnknownCommandIsAUsageError(t *testing.T) {
	code, _, errOut := runCLI(t, []string{"destroy", "aaaa"}, "", noEnv)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, `unknown command "destroy"`)
}

func TestThereIsNoDeleteCommand(t *testing.T) {
	// ADR-0005: the CLI may grant access but not destroy secrets. The absence
	// is the contract, so it gets a test.
	code, _, errOut := runCLI(t, []string{"delete", "aaaa"}, "", noEnv)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, `unknown command "delete"`)

	_, help, _ := runCLI(t, []string{"--help"}, "", noEnv)
	assert.NotContains(t, help, "delete")
	assert.NotContains(t, help, "transfer")
}

func TestHelpListsTheSevenCommands(t *testing.T) {
	code, out, _ := runCLI(t, []string{"--help"}, "", noEnv)
	assert.Equal(t, 0, code)
	for _, command := range []string{"list", "get", "view", "create", "patch", "delegate", "login"} {
		assert.Contains(t, out, "\n  "+command+" ", "command %q is advertised", command)
	}
}

func TestVersionFlagPrintsNameAndVersion(t *testing.T) {
	for _, flag := range []string{"--version", "-V"} {
		code, out, _ := runCLI(t, []string{flag}, "", noEnv)
		assert.Equal(t, 0, code)
		assert.Equal(t, "keyway "+version+"\n", out)
	}
}

func TestJSONAndYAMLRefuseToShareACommandLine(t *testing.T) {
	isolate(t)
	code, _, errOut := runCLI(t,
		[]string{"list", "--json", "--yaml", "--url", "http://x", "--token", "kw-t"}, "", noEnv)
	assert.Equal(t, 2, code, "a flag conflict is a usage error under clap")
	assert.Contains(t, errOut, "--json cannot be used with --yaml")
}

func TestWithoutAProfileTheCLISaysHowToGetOne(t *testing.T) {
	isolate(t)
	code, _, errOut := runCLI(t, []string{"list"}, "", noEnv)
	assert.Equal(t, 1, code, "a missing credential is a runtime error, not a usage one")
	assert.Contains(t, errOut, "no keyway url; run `keyway login <url>` or pass --url")
}

func TestListPrintsWhatTheServerAnswered(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, `[{"id":"aaaa","store":"prod","name":"db","level":"read"}]`, &requests)

	code, out, errOut := runCLI(t,
		[]string{"list", "--url", s.URL, "--token", "kw-t"}, "", noEnv)
	assert.Equal(t, 0, code)
	assert.Equal(t, "aaaa  prod  db  (read)\n", out)
	assert.Empty(t, errOut)

	require.Len(t, requests, 1)
	assert.Equal(t, "/api/secrets", requests[0].URL.Path)
	assert.Equal(t, "Bearer kw-t", requests[0].Header.Get("Authorization"))
}

func TestListFiltersByStoreOnTheClientSide(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t,
		`[{"id":"aaaa","store":"prod","name":"db"},{"id":"bbbb","store":"staging","name":"db"}]`,
		&requests)

	code, out, _ := runCLI(t,
		[]string{"list", "--store", "staging", "--url", s.URL, "--token", "kw-t"}, "", noEnv)
	assert.Equal(t, 0, code)
	assert.Equal(t, "bbbb  staging  db\n", out)
	require.Len(t, requests, 1)
	assert.Empty(t, requests[0].URL.Query(), "the filter never reaches the server")
}

func TestGetPrintsTheBareValue(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, "hunter2", &requests)

	code, out, _ := runCLI(t,
		[]string{"get", "aaaa", "-k", "db_password", "--url", s.URL, "--token", "kw-t"}, "", noEnv)
	assert.Equal(t, 0, code)
	assert.Equal(t, "hunter2\n", out, "the whole point is export X=$(keyway get …)")

	require.Len(t, requests, 1)
	assert.Equal(t, "/api/secrets/aaaa/value", requests[0].URL.Path)
	assert.Equal(t, "key=db_password", requests[0].URL.RawQuery)
}

func TestFlagsBeatTheEnvironmentWhichBeatsNothing(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, "[]", &requests)
	vars := env(map[string]string{"KEYWAY_URL": s.URL, "KEYWAY_TOKEN": "kw-from-env"})

	// Environment alone carries the day.
	code, _, _ := runCLI(t, []string{"list"}, "", vars)
	assert.Equal(t, 0, code)
	require.Len(t, requests, 1)
	assert.Equal(t, "Bearer kw-from-env", requests[0].Header.Get("Authorization"))

	// A flag outranks it.
	code, _, _ = runCLI(t, []string{"list", "--token", "kw-from-flag"}, "", vars)
	assert.Equal(t, 0, code)
	require.Len(t, requests, 2)
	assert.Equal(t, "Bearer kw-from-flag", requests[1].Header.Get("Authorization"))
}

func TestCreateReadsTheValueFromStdinOnDash(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, `{"id":"aaaa","store":"prod","name":"db"}`, &requests)

	code, out, _ := runCLI(t, []string{
		"create", "--store", "prod", "--name", "db", "--value", "-",
		"--url", s.URL, "--token", "kw-t",
	}, "hunter2\n", noEnv)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "id      aaaa")

	require.Len(t, requests, 1)
	payload, err := io.ReadAll(requests[0].Body)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"store":"prod","name":"db","value":"hunter2","note":""}`,
		string(payload), "the trailing newline stays in the terminal")
}

func TestCreateNamesItsMissingFlags(t *testing.T) {
	isolate(t)
	code, _, errOut := runCLI(t, []string{"create", "--store", "prod"}, "", noEnv)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "--name")
	assert.Contains(t, errOut, "--value")
	assert.NotContains(t, errOut, "--store,", "a given flag is not reported missing")
}

func TestPatchPostsTheNewVersion(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, `{"id":"v4","state":"active"}`, &requests)

	code, out, _ := runCLI(t, []string{
		"patch", "aaaa", "--value", "hunter3", "--url", s.URL, "--token", "kw-t",
	}, "", noEnv)
	assert.Equal(t, 0, code)
	assert.Equal(t, "version v4 (active)\n", out)
	assert.Equal(t, "/api/secrets/aaaa/versions", requests[0].URL.Path)
}

func TestDelegateNeedsExactlyOneSubject(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t, "{}", &requests)
	base := []string{"delegate", "aaaa", "--url", s.URL, "--token", "kw-t"}

	// Both at once is a flag conflict — exit 2, as clap draws it.
	code, _, errOut := runCLI(t, append(base, "--user", "sam", "--group", "sre"), "", noEnv)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "--user cannot be used with --group")

	// Neither is caught at run time — exit 1, as eyre::bail! draws it.
	code, _, errOut = runCLI(t, base, "", noEnv)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "give exactly one of --user or --group")

	assert.Empty(t, requests, "no request leaves before the subject makes sense")
}

func TestDelegateSendsTheGrantAndReportsIt(t *testing.T) {
	isolate(t)
	var requests []*http.Request
	s := server(t,
		`{"id":"g1","subject_kind":"group","subject":"sre","level":"write","keys":["a"],"granted_by":"ana"}`,
		&requests)

	code, out, _ := runCLI(t, []string{
		"delegate", "aaaa", "--group", "sre", "--level", "write",
		"--key", "a", "--days", "30", "--note", "rotation",
		"--url", s.URL, "--token", "kw-t",
	}, "", noEnv)
	assert.Equal(t, 0, code)
	assert.Equal(t, "granted write to group sre (keys: a)\n", out)

	require.Len(t, requests, 1)
	assert.Equal(t, "/api/secrets/aaaa/grants", requests[0].URL.Path)
	payload, err := io.ReadAll(requests[0].Body)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"subject_kind":"group","subject":"sre","level":"write","keys":["a"],"days":30,"note":"rotation"}`,
		string(payload))
}

func TestServerRefusalsExitOne(t *testing.T) {
	isolate(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(s.Close)

	code, out, errOut := runCLI(t,
		[]string{"list", "--url", s.URL, "--token", "kw-stale"}, "", noEnv)
	assert.Equal(t, 1, code)
	assert.Empty(t, out)
	assert.Contains(t, errOut, "not signed in, or the token is no longer valid")
}

func TestReadValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		given string
		stdin string
		want  string
	}{
		{"a literal passes through", "hunter2", "ignored", "hunter2"},
		{"a lone dash reads stdin", "-", "from-stdin\n", "from-stdin"},
		{"only trailing newlines are trimmed", "-", "line one\nline two\n\n\n", "line one\nline two"},
		{"inner whitespace survives", "-", "  padded  \n", "  padded  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := readValue(strings.NewReader(tc.stdin), tc.given)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
