package infra

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/domains/secrets/entity"
)

func textEntry(key, text string) ycEntry {
	return ycEntry{Key: key, TextValue: text, hasText: true}
}

func TestLockboxStatusesMapOntoKeywayStates(t *testing.T) {
	assert.Equal(t, entity.VersionEnabled, ycStateOf("ACTIVE"))
	assert.Equal(t, entity.VersionDisabled, ycStateOf("SCHEDULED_FOR_DESTRUCTION"))
	assert.Equal(t, entity.VersionDestroyed, ycStateOf("DESTROYED"))
	assert.Equal(t, entity.VersionDestroyed, ycStateOf("SOMETHING_NEW"))
}

func TestAKvPayloadBecomesFlatJSON(t *testing.T) {
	// The shape every other kv path in keyway expects.
	payload, err := ycPayloadToBytes([]ycEntry{
		textEntry("db_password", "hunter2"),
		textEntry("api_key", "abc"),
	})
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(payload, &parsed))
	assert.Equal(t, "hunter2", parsed["db_password"])
	assert.Equal(t, "abc", parsed["api_key"])
}

func TestALoneValueEntryIsATextSecret(t *testing.T) {
	// What this adapter writes for non-JSON input, so it round-trips.
	payload, err := ycPayloadToBytes([]ycEntry{textEntry("value", "hunter2")})
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), payload)
}

func TestALoneEntryUnderAnotherKeyStaysKv(t *testing.T) {
	payload, err := ycPayloadToBytes([]ycEntry{textEntry("db_password", "hunter2")})
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(payload, &parsed))
	assert.Equal(t, "hunter2", parsed["db_password"])
}

func TestTextAndKvBothRoundTrip(t *testing.T) {
	for _, original := range [][]byte{
		[]byte("hunter2"),
		[]byte(`{"db_password":"hunter2","api_key":"abc"}`),
	} {
		back, err := ycPayloadToBytes(ycBytesToEntries(original))
		require.NoError(t, err)

		// Compared as JSON where it is JSON, since key order is not preserved
		// and does not matter.
		var want map[string]string
		if json.Unmarshal(original, &want) == nil && want != nil {
			var got map[string]string
			require.NoError(t, json.Unmarshal(back, &got))
			assert.Equal(t, want, got)
		} else {
			assert.Equal(t, original, back)
		}
	}
}

func TestABinaryEntryIsDecoded(t *testing.T) {
	payload, err := ycPayloadToBytes([]ycEntry{{Key: "value", BinaryValue: "aHVudGVyMg=="}})
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), payload)
}

func TestASecretWithNoActiveVersionReportsNone(t *testing.T) {
	secret := ycSecret{
		ID:   "e6q",
		Name: "db-creds",
		CurrentVersion: &ycVersion{
			ID:     "v1",
			Status: "DESTROYED",
		},
	}
	assert.Empty(t, ycIntoSecret(secret).LatestVersion)
}
