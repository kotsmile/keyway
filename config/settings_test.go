// A Store's own keys, read where the rest of the config schema is read.
//
// These assertions were the inline `.(string)` assertions of cmd/api's
// mountStores. The wording of the failures is preserved on purpose: an
// operator reading "store "gcp-prod" needs a `project`" is reading the same
// sentence the previous release printed.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAGcpStoreNeedsItsProject(t *testing.T) {
	t.Parallel()
	settings, err := store(t, "id: gcp-prod\ntype: gcp\nallow: [read]\nproject: acme\n").GcpSettings()
	require.NoError(t, err)
	assert.Equal(t, "acme", settings.Project)

	_, err = store(t, "id: gcp-prod\ntype: gcp\nallow: [read]\n").GcpSettings()
	var missing *MissingSettingError
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "store \"gcp-prod\" needs a `project`", missing.Error())
}

func TestAYcStoreNeedsItsFolderAndMayTakeAmbientCredentials(t *testing.T) {
	t.Parallel()
	settings, err := store(t, "id: yc\ntype: yc\nallow: [read]\nfolder: b1g\n").YcSettings()
	require.NoError(t, err)
	assert.Equal(t, "b1g", settings.Folder)
	assert.Empty(t, settings.Secret,
		"a deployment inside YC takes the instance's own metadata identity")

	_, err = store(t, "id: yc\ntype: yc\nallow: [read]\n").YcSettings()
	var missing *MissingSettingError
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "folder", missing.Setting)
}

func TestAK8sStoreNeedsItsNamespace(t *testing.T) {
	t.Parallel()
	settings, err := store(t, "id: k8s\ntype: k8s\nallow: [read]\nnamespace: apps\n").K8sSettings()
	require.NoError(t, err)
	assert.Equal(t, "apps", settings.Namespace)

	_, err = store(t, "id: k8s\ntype: k8s\nallow: [read]\n").K8sSettings()
	var missing *MissingSettingError
	require.ErrorAs(t, err, &missing)
}

func TestAnAwsStoreNeedsNothing(t *testing.T) {
	t.Parallel()
	// An empty region takes the standard provider chain's own, which is what
	// an instance role or IRSA already carries.
	settings, err := store(t, "id: aws\ntype: aws\nallow: [read]\n").AwsSettings()
	require.NoError(t, err)
	assert.Empty(t, settings.Region)

	settings, err = store(t, "id: aws\ntype: aws\nallow: [read]\nregion: eu-west-1\n").AwsSettings()
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", settings.Region)
}

func TestAKeywayStoreReadsItsKeysAndDefaultsTheActiveID(t *testing.T) {
	t.Parallel()
	settings := store(t, "id: local\ntype: keyway\nallow: [read]\n"+
		"key: AQEB\nprevious_keys:\n  v0: AgIC\n").KeywaySettings()
	assert.Equal(t, "v1", settings.KeyID)
	assert.Equal(t, "AQEB", settings.Key)
	assert.Equal(t, map[string]string{"v0": "AgIC"}, settings.PreviousKeys)

	rotated := store(t, "id: local\ntype: keyway\nallow: [read]\nkey_id: v2\nkey: AQEB\n").KeywaySettings()
	assert.Equal(t, "v2", rotated.KeyID)
	assert.Empty(t, rotated.PreviousKeys)
}

func TestASettingThatIsNotAStringReadsAsAbsent(t *testing.T) {
	t.Parallel()
	// Every value in the config file is a string; a `namespace: 123` is a
	// deployment's typo, and it earns the same sentence saying nothing does.
	_, err := store(t, "id: k8s\ntype: k8s\nallow: [read]\nnamespace: 123\n").K8sSettings()
	var missing *MissingSettingError
	require.ErrorAs(t, err, &missing)
}

func TestAnUnknownStoreTypeIsRefusedWhenTheFileIsRead(t *testing.T) {
	t.Parallel()
	// Silently serving four of five declared Stores is worse than not
	// starting, because nobody notices the fifth is missing. The wording is
	// the one cmd/api used to print at mount time.
	var s StoreConfig
	err := yaml.Unmarshal([]byte("id: prod\ntype: hashicorp\nallow: [read]\n"), &s)
	var unknown *UnknownStoreKindError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t,
		`store "prod" names an unknown type "hashicorp"; this build has: keyway, gcp, yc, aws, k8s`,
		unknown.Error())
}

func TestEveryKindThisBuildHasIsAccepted(t *testing.T) {
	t.Parallel()
	for _, kind := range StoreKinds() {
		parsed, err := ParseStoreKind("prod", kind.String())
		require.NoError(t, err)
		assert.Equal(t, kind, parsed)
	}
}

func TestAStoreWithoutAnIDIsRefused(t *testing.T) {
	t.Parallel()
	// An empty id is not a Store anybody could address: its grants could
	// never be told from another empty one's.
	var s StoreConfig
	err := yaml.Unmarshal([]byte("id: \"\"\ntype: gcp\nallow: [read]\n"), &s)
	require.Error(t, err)
}

func TestAnUnknownDirectoryIsRefusedWhenTheFileIsRead(t *testing.T) {
	t.Parallel()
	// The same reasoning as a Store's type: a deployment that asked for live
	// membership checks and silently did not get them is worse than one that
	// does not start.
	var oidc Oidc
	err := yaml.Unmarshal([]byte("directory: okta\n"), &oidc)
	var unknown *UnknownDirectoryError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t,
		`oidc.directory names an unknown kind "okta"; this build has: keycloak`,
		unknown.Error())

	require.NoError(t, yaml.Unmarshal([]byte("directory: keycloak\n"), &oidc))
	assert.Equal(t, DirectoryKeycloak, oidc.Directory)
	assert.True(t, oidc.Directory.IsConfigured())

	require.NoError(t, yaml.Unmarshal([]byte("issuer: x\n"), &oidc))
	assert.False(t, DirectoryNone.IsConfigured(), "unset is the ordinary case")
}
