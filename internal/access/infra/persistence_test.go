// Integration tests against a real PostgreSQL: the SQL here must read and
// write the same rows the Rust queries did, and only a database can say so.
package infra_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/access/entity"
	"github.com/kotsmile/keyway/internal/access/infra"
	"github.com/kotsmile/keyway/internal/postgres/pgtest"
	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
)

// aStore is a store id no other test run or package writes, because the
// database is shared and truncation is not an option.
func aStore(t *testing.T) secretsentity.StoreID {
	t.Helper()
	return secretsentity.StoreID("test-" + uuid.NewString())
}

func aGrant(store secretsentity.StoreID, subject entity.Subject, level entity.Level) entity.Delegation {
	return entity.Delegation{
		ID:        uuid.New(),
		Store:     store,
		Secret:    "db-creds",
		Subject:   subject,
		Level:     level,
		GrantedBy: "carol",
		GrantedAt: time.Now().UTC().Truncate(time.Microsecond),
		Note:      "for the tests",
	}
}

func TestAGrantRoundTripsThroughItsRow(t *testing.T) {
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	grant := aGrant(store, entity.Group("SRE"), entity.Read)
	grant.Keys = []string{"db_password", "api_key"}
	grant.ExpiresAt = &expiry
	require.NoError(t, repo.SaveGrant(ctx, grant))

	grants, err := repo.GrantsOn(ctx, store, "db-creds")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	got := grants[0]
	assert.Equal(t, grant.ID, got.ID)
	assert.Equal(t, entity.Group("SRE"), got.Subject)
	assert.Equal(t, entity.Read, got.Level)
	assert.Equal(t, []string{"db_password", "api_key"}, got.Keys)
	assert.Equal(t, "carol", got.GrantedBy)
	require.NotNil(t, got.ExpiresAt)
	assert.True(t, got.ExpiresAt.Equal(expiry))
	assert.Equal(t, "for the tests", got.Note)
}

func TestSavingAgainReplacesWhatTheSubjectHeld(t *testing.T) {
	// The ON CONFLICT the delegations_one_per_subject index exists for: one
	// subject holds at most one grant per secret.
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	first := aGrant(store, entity.User("alice"), entity.Guest)
	require.NoError(t, repo.SaveGrant(ctx, first))
	second := aGrant(store, entity.User("alice"), entity.Write)
	require.NoError(t, repo.SaveGrant(ctx, second))

	grants, err := repo.GrantsOn(ctx, store, "db-creds")
	require.NoError(t, err)
	require.Len(t, grants, 1, "a second row would make access a max() over rows")
	assert.Equal(t, entity.Write, grants[0].Level)
	// The row keeps its first id: the conflict target updates in place.
	assert.Equal(t, first.ID, grants[0].ID)
}

func TestAnIndefiniteGrantComesBackIndefinite(t *testing.T) {
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	require.NoError(t, repo.SaveGrant(ctx, aGrant(store, entity.User("alice"), entity.Read)))
	grants, err := repo.GrantsOn(ctx, store, "db-creds")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Nil(t, grants[0].ExpiresAt, "NULL expiry is indefinite, not a date")
	assert.Empty(t, grants[0].Keys, "an empty key list is the whole secret")
}

func TestRemoveGrantReportsWhetherThereWasOne(t *testing.T) {
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()

	grant := aGrant(aStore(t), entity.User("alice"), entity.Read)
	require.NoError(t, repo.SaveGrant(ctx, grant))

	removed, err := repo.RemoveGrant(ctx, grant.ID)
	require.NoError(t, err)
	assert.True(t, removed)

	removed, err = repo.RemoveGrant(ctx, grant.ID)
	require.NoError(t, err)
	assert.False(t, removed, "a second revoke has nothing to remove")
}

func TestOwnershipIsReplacedNotAdded(t *testing.T) {
	// A transfer changes who is answerable; it does not produce a second
	// owner.
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	since := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.SetOwner(ctx, entity.Ownership{
		Store: store, Secret: "db-creds", Owner: "alice", Since: since,
	}))
	require.NoError(t, repo.SetOwner(ctx, entity.Ownership{
		Store: store, Secret: "db-creds", Owner: "bob", Since: since.Add(time.Hour),
	}))

	owner, err := repo.OwnerOf(ctx, store, "db-creds")
	require.NoError(t, err)
	require.NotNil(t, owner)
	assert.Equal(t, "bob", owner.Owner)
	assert.True(t, owner.Since.Equal(since.Add(time.Hour)), "a transfer resets `since`")
}

func TestAnUnownedSecretHasNoOwnerRatherThanAnError(t *testing.T) {
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	owner, err := repo.OwnerOf(context.Background(), aStore(t), "db-creds")
	require.NoError(t, err)
	assert.Nil(t, owner)
}

func TestGrantsForSubjectsMatchesKindAndNameTogether(t *testing.T) {
	// The reason the query unnests two arrays instead of an IN list: a person
	// called `sre` must not collect a grant to the team called `sre`
	// (ADR-0003).
	repo := infra.NewPostgresAccessRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	toThePerson := aGrant(store, entity.User("sre"), entity.Write)
	require.NoError(t, repo.SaveGrant(ctx, toThePerson))
	toTheTeam := aGrant(store, entity.Group("sre"), entity.Read)
	require.NoError(t, repo.SaveGrant(ctx, toTheTeam))

	// A caller in the GROUP sre, whose handle is not sre.
	grants, err := repo.GrantsForSubjects(ctx, []entity.Subject{
		entity.User("carol"), entity.Group("sre"),
	})
	require.NoError(t, err)

	var mine []entity.Delegation
	for _, g := range grants {
		if g.Store == store {
			mine = append(mine, g)
		}
	}
	require.Len(t, mine, 1)
	assert.Equal(t, toTheTeam.ID, mine[0].ID, "the person's grant must not reach the team")

	// And nobody at all collects nothing.
	grants, err = repo.GrantsForSubjects(ctx, []entity.Subject{entity.User("nobody-" + store.String())})
	require.NoError(t, err)
	assert.Empty(t, grants)
}
