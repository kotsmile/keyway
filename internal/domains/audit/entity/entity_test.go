package entity_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/domains/audit/entity"
)

func TestEveryActionRoundTripsThroughItsWord(t *testing.T) {
	for _, action := range []entity.Action{
		entity.Create,
		entity.Update,
		entity.Reveal,
		entity.Delete,
		entity.Delegate,
		entity.Revoke,
		entity.Transfer,
	} {
		parsed, ok := entity.ParseAction(string(action))
		require.True(t, ok)
		assert.Equal(t, action, parsed)
	}
}

func TestARecordDefaultsToTheFieldsMostEntriesDoNotSet(t *testing.T) {
	record := entity.NewRecord(entity.Reveal, uuid.New(), "gcp-prod", "db-creds")
	assert.Empty(t, record.Version)
	assert.Empty(t, record.Keys)
	assert.Empty(t, record.Subject)
}
