// What the schema guarantees, against a real PostgreSQL — the Go carry-over
// of the Rust crate's schema tests. Every rule here is one the service would
// otherwise have to remember on every code path, and a rule enforced in one
// place cannot be forgotten in another.
//
// Skipped unless KEYWAY_TEST_DATABASE_URL is set, like every integration test.
package postgres_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/infra/postgres/pgtest"
)

// aStore keys this test's rows away from every other run sharing the
// database; the schema tests insert raw rows and never clean up.
func aStore(t *testing.T) string {
	t.Helper()
	return "test-" + uuid.NewString()
}

func TestMigrationsApplyToAnEmptyDatabase(t *testing.T) {
	// pgtest.DB migrated before answering; what is asserted here is that the
	// tables the Rust migrations promised are all present afterwards.
	db := pgtest.DB(t)
	var names []string
	require.NoError(t, db.SelectContext(context.Background(), &names,
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename`))
	for _, expected := range []string{"audit", "delegations", "ownership", "tokens", "users"} {
		assert.Contains(t, names, expected)
	}
}

func TestOneSubjectHoldsAtMostOneGrantPerSecret(t *testing.T) {
	// Otherwise "what does this open" is a max() over rows rather than an
	// answer, and a grant list means nothing. The service upserts; the index
	// is what refuses a raw second row.
	db := pgtest.DB(t)
	store := aStore(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		`INSERT INTO delegations (id, store, secret, subject_kind, subject_id, level, granted_by)
		 VALUES ($1, $2, 'db-creds', 'user', 'sre', 'read', 'alice')`, uuid.New(), store)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO delegations (id, store, secret, subject_kind, subject_id, level, granted_by)
		 VALUES ($1, $2, 'db-creds', 'user', 'sre', 'write', 'alice')`, uuid.New(), store)
	assert.Error(t, err, "a second grant must be refused, not stacked")
}

func TestARetiredLevelWordIsRefused(t *testing.T) {
	db := pgtest.DB(t)
	store := aStore(t)
	ctx := context.Background()

	for _, retired := range []string{"readonly", "viewer"} {
		_, err := db.ExecContext(ctx,
			`INSERT INTO delegations (id, store, secret, subject_kind, subject_id, level, granted_by)
			 VALUES ($1, $2, 'db-creds', 'user', 'bob', $3, 'alice')`,
			uuid.New(), store, retired)
		assert.Error(t, err, "%q is not a level", retired)
	}
}

func TestASubjectIsAUserOrAGroupAndNothingElse(t *testing.T) {
	// Tokens bind to a user rather than being a subject of their own, so
	// there is no third kind to accept.
	db := pgtest.DB(t)
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO delegations (id, store, secret, subject_kind, subject_id, level, granted_by)
		 VALUES ($1, $2, 'db-creds', 'service', 'eso', 'read', 'alice')`,
		uuid.New(), aStore(t))
	assert.Error(t, err)
}

func TestASecretHasAtMostOneOwner(t *testing.T) {
	// Two owners is a list to argue about rather than an answer to "who do I
	// ask about this". The service upserts on transfer; the primary key is
	// what refuses a raw second row.
	db := pgtest.DB(t)
	store := aStore(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		`INSERT INTO ownership (store, secret, owner) VALUES ($1, 'db-creds', 'alice')`, store)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO ownership (store, secret, owner) VALUES ($1, 'db-creds', 'bob')`, store)
	assert.Error(t, err, "a transfer replaces an owner, never adds one")
}

func TestAnAuditActionNobodyDefinedIsRefused(t *testing.T) {
	db := pgtest.DB(t)
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO audit (actor, action, store, secret) VALUES ('alice', 'peek', $1, 'db')`,
		aStore(t))
	assert.Error(t, err)
}
