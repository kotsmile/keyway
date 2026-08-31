// What the identifiers refuse, and what they must not refuse.
//
// The second half matters as much as the first: these types were introduced
// into a system with live deployments, and a rule tighter than the one that
// was in force orphans somebody's grants or hides somebody's secret. So the
// "accepted" tables below are deliberately full of ugly names — they are all
// names a real backend already allows.

package entity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAStoreIDMustNameAStore(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw     string
		refused bool
	}{
		"the empty id": {raw: "", refused: true},
		// Everything below is a store id some deployment already keyed its
		// grants by. A narrower rule renames them, and renaming one orphans
		// every delegation, ownership and audit row written against it.
		"an ordinary id":     {raw: "gcp-prod"},
		"an id with a dot":   {raw: "acme.prod"},
		"an id with a space": {raw: "the vault"},
		"an id with a slash": {raw: "team/prod"},
		"an upper-case id":   {raw: "PROD"},
		"a unicode id":       {raw: "хранилище"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, err := NewStoreID(tc.raw)
			if tc.refused {
				require.ErrorIs(t, err, ErrStoreIDRequired)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.raw, id.String())
		})
	}
}

func TestASecretNameMustNameASecret(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw     string
		refused bool
	}{
		"the empty name": {raw: "", refused: true},
		// A name is somebody else's contract — an ESO manifest, an existing
		// tool — so keyway refuses none of these. A backend that dislikes one
		// says so at the call, where the reason can be specific.
		"an ordinary name":         {raw: "db-creds"},
		"a name with a slash":      {raw: "a/b"},
		"a name with a space":      {raw: "payment bot"},
		"a name that is only dots": {raw: ".."},
		"a very long name":         {raw: string(make([]byte, 300))},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			secret, err := NewSecretName(tc.raw)
			if tc.refused {
				var invalid *InvalidNameError
				require.ErrorAs(t, err, &invalid)
				// The wording keyway's own Store answered with before the
				// check moved up here.
				assert.Equal(t, "a name is required", invalid.Reason)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.raw, secret.String())
		})
	}
}

func TestTheEmptyVersionIsTheLatest(t *testing.T) {
	t.Parallel()
	// Every adapter maps it to its own backend's notion of current — a stage
	// in AWS, `latest` in Google, the highest number in keyway's own Store.
	assert.True(t, VersionID("").IsLatest())
	assert.False(t, VersionID("1").IsLatest())
	assert.False(t, VersionID("AWSCURRENT").IsLatest())
}

func TestTheIdentifiersMarshalAsTheStringsTheyReplaced(t *testing.T) {
	t.Parallel()
	// The wire did not move: a Secret is the same JSON object it was when
	// these three fields were plain strings.
	encoded, err := json.Marshal(Secret{
		Store:         "gcp-prod",
		Name:          "db-creds",
		LatestVersion: "3",
		Labels:        Metadata{"team": "infra"},
	})
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"store":"gcp-prod","name":"db-creds","labels":{"team":"infra"},"latest_version":"3"}`,
		string(encoded))

	var back Secret
	require.NoError(t, json.Unmarshal(encoded, &back))
	assert.Equal(t, StoreID("gcp-prod"), back.Store)
	assert.Equal(t, SecretName("db-creds"), back.Name)
	assert.Equal(t, VersionID("3"), back.LatestVersion)
}

func TestAVersionStateThisBuildCannotReadIsNotReadable(t *testing.T) {
	t.Parallel()
	// The rule that used to live in each adapter's own switch: a state this
	// build does not understand must not be offered for reveal.
	for word, want := range map[string]VersionState{
		"enabled":     VersionEnabled,
		"disabled":    VersionDisabled,
		"destroyed":   VersionDestroyed,
		"":            VersionDestroyed,
		"ENABLED":     VersionDestroyed,
		"pending":     VersionDestroyed,
		"quarantined": VersionDestroyed,
	} {
		assert.Equal(t, want, ParseVersionState(word), "state %q", word)
	}
	assert.True(t, Version{State: ParseVersionState("enabled")}.Readable())
	assert.False(t, Version{State: ParseVersionState("something new")}.Readable())
}

func TestAVersionStateWritesBackTheWordItWasReadyAs(t *testing.T) {
	t.Parallel()
	// The `state` column holds these three words and no others.
	assert.Equal(t, "enabled", VersionEnabled.Word())
	assert.Equal(t, "disabled", VersionDisabled.Word())
	assert.Equal(t, "destroyed", VersionDestroyed.Word())
	assert.Equal(t, "destroyed", VersionState("nonsense").Word())
}
