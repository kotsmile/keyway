// The staleness policy, tested where it now lives.
//
// The two cache tests came over from internal/identity/infra's Keycloak
// tests unchanged in what they assert: the answer holds until the window
// passes, and a departed account is remembered as absent. They moved because
// the policy did.

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

// countingDirectory answers a fixed script and records how often it was asked
// — the point of a cache being that the provider is asked less.
type countingDirectory struct {
	answer *DirectoryAnswer
	err    error
	calls  int
}

func (d *countingDirectory) Resolve(context.Context, entity.Handle) (*DirectoryAnswer, error) {
	d.calls++
	return d.answer, d.err
}

func TestACachedAnswerIsReturnedUntilItGoesStale(t *testing.T) {
	inner := &countingDirectory{answer: &DirectoryAnswer{
		Enabled: true,
		Groups:  []entity.GroupName{"/SRE"},
	}}
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	directory := NewCachedDirectory(inner, DefaultStaleness, func() time.Time { return now })
	ctx := context.Background()

	answer, err := directory.Resolve(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, answer)
	assert.Equal(t, []entity.GroupName{"/SRE"}, answer.Groups)
	assert.Equal(t, 1, inner.calls)

	// Inside the window the provider is not asked again.
	_, err = directory.Resolve(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// The window is the longest a change may take to bite; past it the answer
	// is stale and the next request asks the directory again.
	now = now.Add(DefaultStaleness)
	_, err = directory.Resolve(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, 2, inner.calls)
}

func TestADepartedAccountIsRememberedAsAbsent(t *testing.T) {
	// Otherwise every request for somebody who left costs a lookup.
	inner := &countingDirectory{answer: nil}
	directory := NewCachedDirectory(inner, DefaultStaleness, time.Now)
	ctx := context.Background()

	answer, err := directory.Resolve(ctx, "gone")
	require.NoError(t, err)
	assert.Nil(t, answer)

	answer, err = directory.Resolve(ctx, "gone")
	require.NoError(t, err)
	assert.Nil(t, answer)
	assert.Equal(t, 1, inner.calls, "a departed account is not looked up twice")
}

func TestAFailedLookupIsNotCached(t *testing.T) {
	// A provider that is down must not fix its silence in place for the whole
	// window: the next request has to try again.
	inner := &countingDirectory{err: errors.New("keycloak is unreachable")}
	directory := NewCachedDirectory(inner, DefaultStaleness, time.Now)
	ctx := context.Background()

	_, err := directory.Resolve(ctx, "alice")
	require.Error(t, err)
	_, err = directory.Resolve(ctx, "alice")
	require.Error(t, err)
	assert.Equal(t, 2, inner.calls)
}

func TestACachedAnswerCannotBeMutatedByItsCaller(t *testing.T) {
	// Two callers share one entry; one of them appending to the groups slice
	// would grant the next caller a membership nobody was given.
	inner := &countingDirectory{answer: &DirectoryAnswer{
		Enabled: true,
		Groups:  []entity.GroupName{"/SRE"},
	}}
	directory := NewCachedDirectory(inner, DefaultStaleness, time.Now)
	ctx := context.Background()

	first, err := directory.Resolve(ctx, "alice")
	require.NoError(t, err)
	first.Groups[0] = "/admins"

	second, err := directory.Resolve(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, []entity.GroupName{"/SRE"}, second.Groups)
}

func TestADisabledAccountIsCachedLikeAnyOtherAnswer(t *testing.T) {
	// The property ADR-0004 buys: disabling somebody cuts every token they
	// issued, within the window — and the check does not cost a lookup per
	// request while it does so.
	inner := &countingDirectory{answer: &DirectoryAnswer{Enabled: false}}
	directory := NewCachedDirectory(inner, DefaultStaleness, time.Now)
	ctx := context.Background()

	for range 3 {
		answer, err := directory.Resolve(ctx, "alice")
		require.NoError(t, err)
		require.NotNil(t, answer)
		assert.False(t, answer.Enabled)
	}
	assert.Equal(t, 1, inner.calls)
}
