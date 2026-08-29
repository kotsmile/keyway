package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTheLadderIsOrdered(t *testing.T) {
	assert.Less(t, Guest, Read)
	assert.Less(t, Read, Write)
}

func TestOnlyReadAndAboveReveal(t *testing.T) {
	assert.False(t, Guest.Reveals())
	assert.True(t, Read.Reveals())
	assert.True(t, Write.Reveals())
}

func TestRoundTripsThroughItsWord(t *testing.T) {
	for _, level := range []Level{Guest, Read, Write} {
		parsed, err := ParseLevel(level.String())
		require.NoError(t, err)
		assert.Equal(t, level, parsed)
	}
}

func TestARetiredSpellingIsRefusedRatherThanDowngraded(t *testing.T) {
	// `readonly` and `viewer` were the pre-rename words upstream. Reading
	// one as Guest would quietly narrow a grant somebody wrote.
	for _, word := range []string{"readonly", "viewer"} {
		_, err := ParseLevel(word)
		var unknown *UnknownLevelError
		require.ErrorAs(t, err, &unknown)
		assert.Equal(t, word, unknown.Word)
	}
}
