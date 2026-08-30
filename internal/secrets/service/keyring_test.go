package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAKeyringReadsItsStoreSettings(t *testing.T) {
	cfg := storeConfig(t, "id: local\ntype: keyway\nallow: [read, edit]\n"+
		"key_id: v2\nkey: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n"+
		"previous_keys:\n  v1: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n")

	keyring, err := KeyringFor(cfg)
	require.NoError(t, err)
	assert.Equal(t, "v2", keyring.ActiveID())
}

func TestAKeyIDDefaultsToV1(t *testing.T) {
	cfg := storeConfig(t, "id: local\ntype: keyway\nallow: [read]\n"+
		"key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n")

	keyring, err := KeyringFor(cfg)
	require.NoError(t, err)
	assert.Equal(t, "v1", keyring.ActiveID())
}

func TestAStoreWithNoKeyIsRefused(t *testing.T) {
	// Caught at mount rather than on the first write.
	cfg := storeConfig(t, "id: local\ntype: keyway\nallow: [read]\n")
	_, err := KeyringFor(cfg)
	assert.Error(t, err)
}
