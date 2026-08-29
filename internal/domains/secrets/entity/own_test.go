package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func version(id string, state VersionState) Version {
	return Version{ID: id, State: state}
}

func TestAnOwnVersionRoundTrips(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := SealOwnVersion(keyring, "local", "db-creds", 1, []byte("hunter2"))
	require.NoError(t, err)

	opened, err := sealed.Open(keyring)
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), opened)
}

func TestADestroyedVersionHasNothingToReveal(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := SealOwnVersion(keyring, "local", "db-creds", 1, []byte("hunter2"))
	require.NoError(t, err)
	sealed.State = VersionDestroyed

	_, err = sealed.Open(keyring)
	var missing *NoSuchVersionError
	assert.ErrorAs(t, err, &missing)
}

func TestAVersionMovedToAnotherSecretWillNotOpen(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := SealOwnVersion(keyring, "local", "db-creds", 1, []byte("hunter2"))
	require.NoError(t, err)
	sealed.Secret = "api-key"

	_, err = sealed.Open(keyring)
	assert.Error(t, err)
}

func TestAVersionRenumberedWillNotOpen(t *testing.T) {
	// The number is bound into the tag, so rows cannot be shuffled.
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := SealOwnVersion(keyring, "local", "db-creds", 1, []byte("hunter2"))
	require.NoError(t, err)
	sealed.Number = 2

	_, err = sealed.Open(keyring)
	assert.Error(t, err)
}

func TestAnOwnVersionSealedUnderARetiredKeyStillOpens(t *testing.T) {
	old := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := SealOwnVersion(old, "local", "db-creds", 1, []byte("hunter2"))
	require.NoError(t, err)
	assert.Equal(t, "v1", sealed.Sealed.KeyID)

	rotated := ring(t, "v2", map[string]string{"v1": keyA, "v2": keyB})
	opened, err := sealed.Open(rotated)
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), opened)
}

func TestTheNextNumberFollowsTheHighest(t *testing.T) {
	assert.Equal(t, int64(1), NextNumber(nil))
	assert.Equal(t, int64(2), NextNumber([]Version{version("1", VersionEnabled)}))
	// Including versions that can no longer be read: reusing a number would
	// make two different payloads share an identity.
	assert.Equal(t, int64(3), NextNumber([]Version{
		version("1", VersionEnabled),
		version("2", VersionDestroyed),
	}))
}

func TestTheLatestIsTheNewestReadableOne(t *testing.T) {
	versions := []Version{
		version("1", VersionEnabled),
		version("2", VersionEnabled),
		version("3", VersionDestroyed),
	}
	latest, ok := Latest(versions)
	require.True(t, ok)
	assert.Equal(t, "2", latest.ID)
}

func TestASecretWithNoReadableVersionHasNoLatest(t *testing.T) {
	_, ok := Latest(nil)
	assert.False(t, ok)
	_, ok = Latest([]Version{version("1", VersionDestroyed)})
	assert.False(t, ok)
}

func TestAVersionNumberThatIsNotANumberIsRefused(t *testing.T) {
	_, err := ParseNumber("latest")
	assert.Error(t, err)
	_, err = ParseNumber("1; DROP TABLE")
	assert.Error(t, err)
	number, err := ParseNumber("7")
	require.NoError(t, err)
	assert.Equal(t, int64(7), number)
}
