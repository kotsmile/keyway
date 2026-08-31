package entity

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func labelled(store StoreID, name SecretName, labels map[string]string) Secret {
	return Secret{Store: store, Name: name, Labels: labels}
}

func TestALabelIsTheAnswerWhenTheBackendCarriesOne(t *testing.T) {
	known := uuid.MustParse("7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f")
	s := labelled("gcp-prod", "db-creds", map[string]string{IDLabel: known.String()})
	assert.Equal(t, known, IDFor(s))
}

func TestAnUnlabelledSecretIsAddressableFromTheFirstRequest(t *testing.T) {
	// The reason this ships without a backfill.
	s := labelled("gcp-prod", "db-creds", nil)
	assert.Equal(t, Derive("gcp-prod", "db-creds"), IDFor(s))
}

func TestDerivationIsStableAcrossProcesses(t *testing.T) {
	assert.Equal(t, Derive("gcp-prod", "db-creds"), Derive("gcp-prod", "db-creds"),
		"three replicas must answer the same uuid without coordinating")
}

func TestDerivationMatchesTheRustServer(t *testing.T) {
	// v5 over the fixed namespace — the id the Rust server answered for the
	// same (store, name) must be the id the Go server answers, or the port
	// silently renames every unlabelled secret.
	derived := Derive("gcp-prod", "db-creds")
	assert.Equal(t, uuid.Version(5), derived.Version())
	assert.Equal(t, uuid.RFC4122, derived.Variant())
	// The golden value, computed independently (python uuid5 over the same
	// namespace and name) — RFC 4122 v5 is what Rust's Uuid::new_v5 speaks.
	assert.Equal(t, uuid.MustParse("edc3a52f-0020-5c86-9867-59cfe02db94a"), derived)
}

func TestTheSameNameInTwoStoresIsTwoSecrets(t *testing.T) {
	assert.NotEqual(t, Derive("gcp-prod", "db-creds"), Derive("aws-prod", "db-creds"))
}

func TestAMalformedLabelFallsBackRatherThanFailing(t *testing.T) {
	// Somebody else's tooling may have written the key. Refusing to address
	// the secret at all would be worse than deriving one.
	s := labelled("gcp-prod", "db-creds", map[string]string{IDLabel: "not-a-uuid"})
	assert.Equal(t, Derive("gcp-prod", "db-creds"), IDFor(s))
	assert.False(t, IsLabelled(s))
}

func TestAdoptionWritesTheDerivedIDAndKeepsTheRest(t *testing.T) {
	s := labelled("gcp-prod", "db-creds", map[string]string{"team": "infra"})
	adopted := AdoptionLabels(s)
	require.NotNil(t, adopted, "needs adopting")

	assert.Equal(t, Derive("gcp-prod", "db-creds").String(), adopted[IDLabel])
	assert.Equal(t, "infra", adopted["team"])
}

func TestAnAdoptedSecretIsNotAdoptedTwice(t *testing.T) {
	known := Derive("gcp-prod", "db-creds").String()
	s := labelled("gcp-prod", "db-creds", map[string]string{IDLabel: known})
	assert.Nil(t, AdoptionLabels(s))
}

func TestALabelledSecretKeepsItsIDWhenRenamed(t *testing.T) {
	// The whole point of the label: an id that stops depending on the name.
	known := uuid.MustParse("7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f")
	before := labelled("gcp-prod", "old-name", map[string]string{IDLabel: known.String()})
	after := labelled("gcp-prod", "new-name", map[string]string{IDLabel: known.String()})

	assert.Equal(t, IDFor(before), IDFor(after))
}
