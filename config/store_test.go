package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func store(t *testing.T, text string) StoreConfig {
	t.Helper()
	var s StoreConfig
	require.NoError(t, yaml.Unmarshal([]byte(text), &s), "valid store")
	return s
}

func TestAdapterKeysLandInSettingsRatherThanFailingTheParse(t *testing.T) {
	s := store(t, "id: gcp-prod\ntype: gcp\nallow: [read]\nproject: acme\n")
	assert.Equal(t, "acme", s.Settings["project"])
	_, known := s.Settings["id"]
	assert.False(t, known, "known keys are not settings")
}

func TestProtectDefaultsToTheReconcilerMarkers(t *testing.T) {
	s := store(t, "id: k8s\ntype: k8s\nallow: [read, edit]\n")
	assert.Equal(t, ReconcilerDefaults(), s.Protect)
	assert.True(t, s.Select.IsEmpty(), "saying nothing about select exposes everything")
}

func TestProtectCanBeEmptiedDeliberately(t *testing.T) {
	s := store(t, "id: k8s\ntype: k8s\nallow: [read]\nprotect: {}\n")
	assert.True(t, s.Protect.IsEmpty())
}

func TestVerbsAreIndependentOfOneAnother(t *testing.T) {
	s := store(t, "id: prod\ntype: gcp\nallow: [read, edit]\n")
	assert.True(t, s.Can(Read))
	assert.True(t, s.Can(Edit))
	assert.False(t, s.Can(Create), "editing is not creating")
	assert.False(t, s.Can(Delete), "editing is not destroying")
}

func TestATitleFallsBackToTheID(t *testing.T) {
	s := store(t, "id: gcp-prod\ntype: gcp\nallow: [read]\n")
	assert.Equal(t, "gcp-prod", s.DisplayTitle())
}

func TestAnUnknownVerbIsRefused(t *testing.T) {
	var s StoreConfig
	err := yaml.Unmarshal([]byte("id: prod\ntype: gcp\nallow: [write]\n"), &s)
	require.Error(t, err)
}

func TestAStoreWithoutAllowIsRefused(t *testing.T) {
	var s StoreConfig
	err := yaml.Unmarshal([]byte("id: prod\ntype: gcp\n"), &s)
	require.Error(t, err)
}
