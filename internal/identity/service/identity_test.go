package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

// fakeRepo remembers in memory what the Postgres repo remembers in a table.
type fakeRepo struct {
	users map[entity.Handle]*entity.RememberedUser
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{users: map[entity.Handle]*entity.RememberedUser{}}
}

func (r *fakeRepo) Remember(_ context.Context, user *entity.RememberedUser) error {
	copied := *user
	r.users[user.Handle] = &copied
	return nil
}

func (r *fakeRepo) Recall(_ context.Context, handle entity.Handle) (*entity.RememberedUser, error) {
	return r.users[handle], nil
}

// fakeDirectory answers the same thing for everybody.
type fakeDirectory struct {
	answer *DirectoryAnswer
}

func (d *fakeDirectory) Resolve(context.Context, entity.Handle) (*DirectoryAnswer, error) {
	return d.answer, nil
}

func TestASignInReplacesTheGroupsRatherThanMerging(t *testing.T) {
	// Somebody removed from a team must lose it on their next sign-in; a
	// merge would mean membership only ever grew.
	repo := newFakeRepo()
	service := NewService(repo, nil)
	ctx := context.Background()

	first := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	require.NoError(t, service.SignIn(ctx, "alice", []entity.GroupName{"SRE", "platform"},
		"alice@example.com", "Alice", first))
	second := first.Add(24 * time.Hour)
	require.NoError(t, service.SignIn(ctx, "alice", []entity.GroupName{"platform"},
		"alice@example.com", "Alice", second))

	user, err := service.Recall(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, []entity.GroupName{"platform"}, user.Groups)
	assert.True(t, user.LastLogin.Equal(second))
}

func TestATokenActsWithTheRememberedGroupsWithoutADirectory(t *testing.T) {
	// ADR-0004: the claim as it stood at the last sign-in, so a grant to a
	// team is visible to the team's bots.
	repo := newFakeRepo()
	service := NewService(repo, nil)
	ctx := context.Background()
	require.NoError(t, service.SignIn(ctx, "alice", []entity.GroupName{"SRE"},
		"alice@example.com", "Alice", time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)))

	actor, err := service.ActorForToken(ctx, "alice", []entity.Role{entity.RoleAdmin}, "7f3a9c2e")
	require.NoError(t, err)
	require.NotNil(t, actor)
	assert.Equal(t, []string{"SRE"}, actor.GroupNames())
	assert.True(t, actor.IsAdmin())
	id, viaToken := actor.TokenID()
	require.True(t, viaToken)
	assert.Equal(t, "7f3a9c2e", id)
}

func TestATokenOfSomebodyNeverSeenStillActsWithNoGroups(t *testing.T) {
	// Minting a token requires a browser session, so this arises only for a
	// database predating the port — and "no teams yet" is not a refusal.
	service := NewService(newFakeRepo(), nil)

	actor, err := service.ActorForToken(context.Background(), "ghost", nil, "id")
	require.NoError(t, err)
	require.NotNil(t, actor)
	assert.Empty(t, actor.GroupNames())
}

func TestADirectoryReplacesRememberedGroupsWithALiveAnswer(t *testing.T) {
	repo := newFakeRepo()
	service := NewService(repo, &fakeDirectory{answer: &DirectoryAnswer{
		Enabled: true,
		Groups:  []entity.GroupName{"/platform"},
	}})
	ctx := context.Background()
	// What was remembered says SRE; the live answer must win.
	require.NoError(t, service.SignIn(ctx, "alice", []entity.GroupName{"SRE"},
		"alice@example.com", "Alice", time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)))

	actor, err := service.ActorForToken(ctx, "alice", nil, "id")
	require.NoError(t, err)
	require.NotNil(t, actor)
	assert.Equal(t, []string{"/platform"}, actor.GroupNames())
}

func TestADisabledAccountResolvesToNoActor(t *testing.T) {
	// What a Directory buys back: disable the account and every token it
	// issued dies (ADR-0004).
	service := NewService(newFakeRepo(), &fakeDirectory{answer: &DirectoryAnswer{Enabled: false}})

	actor, err := service.ActorForToken(context.Background(), "alice", nil, "id")
	require.NoError(t, err)
	assert.Nil(t, actor)
}

func TestAnAccountGoneFromTheDirectoryResolvesToNoActor(t *testing.T) {
	service := NewService(newFakeRepo(), &fakeDirectory{answer: nil})

	actor, err := service.ActorForToken(context.Background(), "gone", nil, "id")
	require.NoError(t, err)
	assert.Nil(t, actor)
}

func TestHasDirectorySaysWhetherOneIsConfigured(t *testing.T) {
	// The console warns when delegating to a group without one, because an
	// API token cannot see such a grant.
	assert.False(t, NewService(newFakeRepo(), nil).HasDirectory())
	assert.True(t, NewService(newFakeRepo(), &fakeDirectory{}).HasDirectory())
}
