package entity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/access/entity"
)

func TestTheLadderIsOrdered(t *testing.T) {
	assert.Less(t, entity.Guest, entity.Read)
	assert.Less(t, entity.Read, entity.Write)
}

func TestOnlyReadAndAboveReveal(t *testing.T) {
	assert.False(t, entity.Guest.Reveals())
	assert.True(t, entity.Read.Reveals())
	assert.True(t, entity.Write.Reveals())
}

func TestRoundTripsThroughItsWord(t *testing.T) {
	for _, level := range []entity.Level{entity.Guest, entity.Read, entity.Write} {
		parsed, err := entity.ParseLevel(level.String())
		require.NoError(t, err)
		assert.Equal(t, level, parsed)
	}
}

func TestARetiredSpellingIsRefusedRatherThanDowngraded(t *testing.T) {
	// `readonly` and `viewer` were the pre-rename words upstream. Reading
	// one as Guest would quietly narrow a grant somebody wrote.
	for _, retired := range []string{"readonly", "viewer"} {
		_, err := entity.ParseLevel(retired)
		var unknown *entity.UnknownLevelError
		require.ErrorAs(t, err, &unknown, "%q must not parse", retired)
	}
}
