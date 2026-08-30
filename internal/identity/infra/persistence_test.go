package infra

// What the users table guarantees, against a real Postgres.
//
// Skipped unless KEYWAY_TEST_DATABASE_URL is set, so `go test` stays
// runnable with no database. CI sets it against a service container.

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/identity/entity"
	"github.com/kotsmile/keyway/internal/postgres"
)

// testDB is a migrated database of this test's own.
//
// Each test gets a private schema rather than sharing `public`: these run in
// parallel, and a shared schema means one test's fixtures are another's
// mystery failure.
func testDB(t *testing.T) *sqlx.DB {
	t.Helper()
	url := os.Getenv("KEYWAY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KEYWAY_TEST_DATABASE_URL is not set")
	}

	suffix := make([]byte, 16)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	schema := fmt.Sprintf("test_%x", suffix)

	admin, err := sqlx.Connect("postgres", url)
	require.NoError(t, err, "connect to test database")
	// Safe by construction: `schema` is `test_` plus generated hex, so there
	// is nothing in it a caller could have influenced.
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err, "create test schema")
	require.NoError(t, admin.Close())

	// lib/pq passes unknown parameters to the server as runtime settings, so
	// search_path scopes every unqualified name to this test's schema.
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	db, err := sqlx.Connect("postgres", url+separator+"search_path="+schema)
	require.NoError(t, err, "connect to the test schema")
	t.Cleanup(func() { _ = db.Close() })

	// goose configures itself through package-level state, so two parallel
	// tests migrating at once are a data race; the schemas stay private, only
	// the migrating is serialized.
	migrateMu.Lock()
	defer migrateMu.Unlock()
	require.NoError(t, postgres.Migrate(context.Background(), db), "migrations apply")
	return db
}

var migrateMu sync.Mutex

func TestRememberedGroupsSurviveARoundTrip(t *testing.T) {
	t.Parallel()
	// The claim as it stood at the last sign-in (ADR-0004), so a token can
	// act as its holder in full.
	repo := NewPostgresIdentityRepo(testDB(t))
	ctx := context.Background()

	at := time.Date(2026, 8, 29, 9, 30, 0, 123456000, time.UTC)
	require.NoError(t, repo.Remember(ctx, &entity.RememberedUser{
		Handle:    "alice",
		Groups:    []string{"SRE", "platform"},
		Email:     "alice@example.com",
		Name:      "Alice",
		LastLogin: at,
	}))

	user, err := repo.Recall(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Handle)
	assert.Equal(t, []string{"SRE", "platform"}, user.Groups)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "Alice", user.Name)
	// timestamptz keeps microseconds and may come back in another zone;
	// Equal compares the instant.
	assert.True(t, user.LastLogin.Equal(at), "want %v, got %v", at, user.LastLogin)
}

func TestASignInReplacesTheGroupsInTheRow(t *testing.T) {
	t.Parallel()
	// REPLACED rather than merged: a person removed from a team must lose it
	// on their next sign-in.
	repo := NewPostgresIdentityRepo(testDB(t))
	ctx := context.Background()

	first := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	require.NoError(t, repo.Remember(ctx, &entity.RememberedUser{
		Handle: "alice", Groups: []string{"SRE", "platform"},
		Email: "alice@example.com", Name: "Alice", LastLogin: first,
	}))
	second := first.Add(24 * time.Hour)
	require.NoError(t, repo.Remember(ctx, &entity.RememberedUser{
		Handle: "alice", Groups: []string{"platform"},
		Email: "alice@acme.example.com", Name: "Alice A.", LastLogin: second,
	}))

	user, err := repo.Recall(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, []string{"platform"}, user.Groups)
	assert.Equal(t, "alice@acme.example.com", user.Email)
	assert.Equal(t, "Alice A.", user.Name)
	assert.True(t, user.LastLogin.Equal(second))
}

func TestNoGroupsIsRememberedAsAnEmptyClaimNotNull(t *testing.T) {
	t.Parallel()
	// The Rust server bound a Vec and could never write NULL; the column is
	// NOT NULL DEFAULT '{}' and a nil slice must land the same way.
	repo := NewPostgresIdentityRepo(testDB(t))
	ctx := context.Background()

	require.NoError(t, repo.Remember(ctx, &entity.RememberedUser{
		Handle: "loner", LastLogin: time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC),
	}))

	user, err := repo.Recall(ctx, "loner")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Empty(t, user.Groups)
}

func TestRecallingSomebodyWhoNeverSignedInIsNobody(t *testing.T) {
	t.Parallel()
	repo := NewPostgresIdentityRepo(testDB(t))

	user, err := repo.Recall(context.Background(), "ghost")
	require.NoError(t, err)
	assert.Nil(t, user)
}
