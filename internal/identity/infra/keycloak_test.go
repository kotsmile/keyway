package infra

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityservice "github.com/kotsmile/keyway/internal/identity/service"
)

func TestTheAdminBaseIsDerivedFromTheIssuer(t *testing.T) {
	// Configuring them separately means they can only ever disagree by
	// mistake, and that mistake authorises against the wrong population.
	directory, err := NewKeycloakDirectory("https://id.example.com/realms/acme", "keyway", "s3cret")
	require.NoError(t, err)
	assert.Equal(t, "https://id.example.com/admin/realms/acme", directory.adminBase)
	assert.Equal(t,
		"https://id.example.com/realms/acme/protocol/openid-connect/token",
		directory.tokenURL)
}

func TestATrailingSlashDoesNotChangeTheAnswer(t *testing.T) {
	directory, err := NewKeycloakDirectory("https://id.example.com/realms/acme/", "keyway", "x")
	require.NoError(t, err)
	assert.Equal(t, "https://id.example.com/admin/realms/acme", directory.adminBase)
}

func TestAnIssuerThatIsNotARealmIsRefusedAtBoot(t *testing.T) {
	// Another OIDC provider does not have this API, and failing here says so
	// rather than failing on the first sign-in.
	_, err := NewKeycloakDirectory("https://accounts.google.com", "keyway", "x")
	require.Error(t, err)
}

func TestACachedAnswerIsReturnedUntilItGoesStale(t *testing.T) {
	directory, err := NewKeycloakDirectory("https://id.example.com/realms/acme", "keyway", "x")
	require.NoError(t, err)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	directory.now = func() time.Time { return now }

	_, known := directory.cached("alice")
	assert.False(t, known)

	directory.remember("alice", &identityservice.DirectoryAnswer{
		Enabled: true,
		Groups:  []string{"/SRE"},
	})
	answer, known := directory.cached("alice")
	require.True(t, known)
	require.NotNil(t, answer)
	assert.Equal(t, []string{"/SRE"}, answer.Groups)

	// The window is the longest a change may take to bite; past it the
	// answer is stale and the next request asks Keycloak again.
	now = now.Add(cacheFor)
	_, known = directory.cached("alice")
	assert.False(t, known)
}

func TestADepartedAccountIsRememberedAsAbsent(t *testing.T) {
	// Otherwise every request for somebody who left costs a lookup.
	directory, err := NewKeycloakDirectory("https://id.example.com/realms/acme", "keyway", "x")
	require.NoError(t, err)
	directory.remember("gone", nil)

	answer, known := directory.cached("gone")
	assert.True(t, known)
	assert.Nil(t, answer)
}
