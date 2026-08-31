package infra

// The caching tests that used to live here moved with the policy they test,
// into internal/identity/service: how stale an answer may be is a decision
// about how fast a revocation bites, not a property of Keycloak's REST API.
import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
