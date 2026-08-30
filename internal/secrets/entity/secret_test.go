package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOnlyAnEnabledVersionCanBeRevealed(t *testing.T) {
	version := func(state VersionState) Version {
		return Version{ID: "7", State: state}
	}
	assert.True(t, version(VersionEnabled).Readable())
	assert.False(t, version(VersionDisabled).Readable())
	assert.False(t, version(VersionDestroyed).Readable())
}

func TestAReferenceNamesTheStoreAndTheName(t *testing.T) {
	secret := Secret{Store: "gcp-prod", Name: "db-creds"}
	assert.Equal(t, "gcp-prod/db-creds", secret.Reference())
}
