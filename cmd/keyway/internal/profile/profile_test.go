package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolate points $HOME at a scratch directory so no test reads or writes a
// real ~/.keyway/config.yml.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func saveProfile(t *testing.T, home, text string) {
	t.Helper()
	dir := filepath.Join(home, ".keyway")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(text), 0o600))
}

func str(s string) *string { return &s }

func TestResolveWithNothingSavedNeedsBothFlags(t *testing.T) {
	isolate(t)

	_, err := Resolve(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no keyway url")

	_, err = Resolve(str("https://kw.example"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token")
}

func TestResolveFallsBackToTheSavedProfile(t *testing.T) {
	home := isolate(t)
	saveProfile(t, home, "url: https://saved.example\ntoken: kw-saved\n")

	resolved, err := Resolve(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://saved.example", resolved.URL)
	assert.Equal(t, "kw-saved", resolved.Token)
}

func TestResolvePrefersTheFlagOverTheSavedProfile(t *testing.T) {
	home := isolate(t)
	saveProfile(t, home, "url: https://saved.example\ntoken: kw-saved\n")

	resolved, err := Resolve(str("https://flag.example"), str("kw-flag"))
	require.NoError(t, err)
	assert.Equal(t, "https://flag.example", resolved.URL)
	assert.Equal(t, "kw-flag", resolved.Token)
}

func TestResolveMixesAFlagWithTheSavedRemainder(t *testing.T) {
	home := isolate(t)
	saveProfile(t, home, "url: https://saved.example\ntoken: kw-saved\n")

	resolved, err := Resolve(str("https://flag.example"), nil)
	require.NoError(t, err)
	assert.Equal(t, "https://flag.example", resolved.URL)
	assert.Equal(t, "kw-saved", resolved.Token, "only the given half is overridden")
}

func TestResolveTakesAnEmptyFlagAtItsWord(t *testing.T) {
	home := isolate(t)
	saveProfile(t, home, "url: https://saved.example\ntoken: kw-saved\n")

	// An empty string was still given; it must not fall through to the saved
	// value, matching clap's Some("") over the profile.
	resolved, err := Resolve(str(""), nil)
	require.NoError(t, err)
	assert.Equal(t, "", resolved.URL)
}

func TestResolveReportsAnUnreadableProfile(t *testing.T) {
	home := isolate(t)
	saveProfile(t, home, "url: [broken\n")

	_, err := Resolve(nil, nil)
	require.Error(t, err, "a corrupt profile is an error, not a silent fallback")
}

func TestLoginSavesTheProfileWithTightPermissions(t *testing.T) {
	home := isolate(t)
	restore := openBrowser
	openBrowser = func(string) error { return nil }
	defer func() { openBrowser = restore }()

	var out strings.Builder
	// The trailing slash is trimmed and the token is trimmed of whitespace.
	err := Login(strings.NewReader("  kw-abc123\n"), &out, "https://kw.example/")
	require.NoError(t, err)

	file := filepath.Join(home, ".keyway", "config.yml")
	text, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "url: https://kw.example\ntoken: kw-abc123\n", string(text))

	info, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"a long-lived credential must not be world-readable")

	assert.Contains(t, out.String(), "Open https://kw.example/tokens and create a token")
	assert.Contains(t, out.String(), "Saved to "+file+".")

	// And what login saved is what resolve finds.
	resolved, err := Resolve(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://kw.example", resolved.URL)
	assert.Equal(t, "kw-abc123", resolved.Token)
}

func TestLoginRefusesAForeignLookingToken(t *testing.T) {
	home := isolate(t)
	restore := openBrowser
	openBrowser = func(string) error { return nil }
	defer func() { openBrowser = restore }()

	var out strings.Builder
	err := Login(strings.NewReader("ghp_notakeywaytoken\n"), &out, "https://kw.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start with `kw-`")

	_, statErr := os.Stat(filepath.Join(home, ".keyway", "config.yml"))
	assert.True(t, os.IsNotExist(statErr), "nothing is saved on refusal")
}

func TestLoginMentionsABrowserThatWouldNotOpen(t *testing.T) {
	isolate(t)
	restore := openBrowser
	openBrowser = func(string) error { return assert.AnError }
	defer func() { openBrowser = restore }()

	var out strings.Builder
	err := Login(strings.NewReader("kw-abc\n"), &out, "https://kw.example")
	require.NoError(t, err, "a browser is a convenience, not a requirement")
	assert.Contains(t, out.String(), "could not open a browser")
}
