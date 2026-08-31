package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
)

const sample = `
postgres:
  addr: localhost:5432
  name: keyway
  user: keyway
  password: ${env:PGPASS}

oidc:
  issuer: https://id.example.com/realms/acme
  client_id: keyway
  client_secret: ${env:OIDC_SECRET}

stores:
  - id: gcp-prod
    type: gcp
    title: Google Cloud (production)
    allow: [read, edit]
    project: acme-prod
    select:
      labels:
        keyway: "true"
`

func env(pairs map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := pairs[name]
		return value, ok
	}
}

func loadSample(t *testing.T, yaml string, pairs map[string]string) (Config, error) {
	t.Helper()
	return FromString(yaml, "config.yml", env(pairs))
}

func TestReadsAWholeFile(t *testing.T) {
	config, err := loadSample(t, sample, map[string]string{"PGPASS": "hunter2", "OIDC_SECRET": "s3cret"})
	require.NoError(t, err)

	assert.Equal(t, "hunter2", config.Postgres.Password)
	assert.Equal(t, "s3cret", config.Oidc.ClientSecret)
	require.Len(t, config.Stores, 1)
	assert.Equal(t, secretsentity.StoreID("gcp-prod"), config.Stores[0].ID)
	assert.Equal(t, KindGcp, config.Stores[0].Kind)
	assert.True(t, config.Stores[0].Can(Read))
	assert.False(t, config.Stores[0].Can(Delete))
}

func TestDefaultsFillInWhatAShortFileOmits(t *testing.T) {
	config, err := loadSample(t, sample, map[string]string{"PGPASS": "x", "OIDC_SECRET": "y"})
	require.NoError(t, err)
	assert.Equal(t, ":8080", config.Server.Address)
	assert.Equal(t, "keyway", config.Branding.Name)
	assert.Equal(t, "groups", config.Oidc.GroupsClaim)
	// Not `disable`: a deployment that has said nothing about TLS to its
	// database has not thereby asked for none.
	assert.Equal(t, "require", config.Postgres.SSLMode)
}

func TestAnUnsetPlaceholderIsFatal(t *testing.T) {
	_, err := loadSample(t, sample, map[string]string{"PGPASS": "hunter2"})
	var unresolved *UnresolvedError
	require.ErrorAs(t, err, &unresolved)
	require.Len(t, unresolved.Unresolved, 1)
	assert.Equal(t, "oidc.client_secret", unresolved.Unresolved[0].Path)
}

func TestAdapterSettingsAreKeptForTheStoreToRead(t *testing.T) {
	config, err := loadSample(t, sample, map[string]string{"PGPASS": "x", "OIDC_SECRET": "y"})
	require.NoError(t, err)
	assert.Equal(t, "acme-prod", config.Stores[0].Settings["project"],
		"a store's own keys belong to its SecretManager, not to this schema")
}

func TestTwoStoresOnOneIDFailTheBoot(t *testing.T) {
	yaml := sample + "  - id: gcp-prod\n    type: gcp\n    allow: [read]\n    project: other\n"
	_, err := loadSample(t, yaml, map[string]string{"PGPASS": "x", "OIDC_SECRET": "y"})
	var duplicate *DuplicateStoreError
	require.ErrorAs(t, err, &duplicate)
}

func TestAMisspelledTopLevelKeyIsRefused(t *testing.T) {
	// `postgress:` should not read as "no postgres block configured".
	yaml := strings.Replace(sample, "postgres:", "postgress:", 1)
	_, err := loadSample(t, yaml, map[string]string{"PGPASS": "x", "OIDC_SECRET": "y"})
	var parse *ParseError
	require.ErrorAs(t, err, &parse)
}

func TestAMissingRequiredBlockIsRefused(t *testing.T) {
	_, err := FromString("oidc:\n  issuer: \"\"\n", "config.yml", env(nil))
	var parse *ParseError
	require.ErrorAs(t, err, &parse)
}
