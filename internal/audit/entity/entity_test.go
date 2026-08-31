package entity_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/audit/entity"
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

func TestOnlyTheSevenActionsTheColumnAllowsAreKnown(t *testing.T) {
	// The `action` column carries a CHECK constraint listing exactly these
	// words. IsKnown is the mirror of it, so an entry nothing could have
	// meant is refused where the word was chosen rather than by PostgreSQL,
	// which would report a constraint name and drop the entry.
	for _, action := range []entity.Action{
		entity.Create, entity.Update, entity.Reveal, entity.Delete,
		entity.Delegate, entity.Revoke, entity.Transfer,
	} {
		assert.True(t, action.IsKnown(), "%q is in the CHECK constraint", action)
	}
	for _, action := range []entity.Action{"", "read", "REVEAL", "rotate"} {
		assert.False(t, action.IsKnown(), "%q is not", action)
	}

	// And the refusal says which word and what this build has.
	err := &entity.UnknownActionError{Action: "rotate"}
	assert.Contains(t, err.Error(), `"rotate"`)
	assert.Contains(t, err.Error(), "create, update, reveal, delete, delegate, revoke, transfer")
}
