// Package pgtest opens the database the integration tests run against.
//
// The Rust suite ran its persistence code only through the HTTP tests; the Go
// port tests each repository directly, against a real PostgreSQL, because a
// mocked query proves nothing about the SQL the Rust server left behind.
package pgtest

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/kotsmile/keyway/internal/infra/postgres"
)

// EnvURL names the database the tests may write to. Unset means skip: a unit
// `go test ./...` must pass on a machine with nothing running.
const EnvURL = "KEYWAY_TEST_DATABASE_URL"

var migrateOnce sync.Once

// DB opens the test database and brings its schema up to date, or skips the
// test when no database is offered.
//
// Tests sharing the database must key their rows uniquely (a uuid-suffixed
// store name) rather than truncate: `go test ./...` runs packages in
// parallel, and a TRUNCATE in one package is data loss in another.
func DB(t *testing.T) *sqlx.DB {
	t.Helper()
	url := os.Getenv(EnvURL)
	if url == "" {
		t.Skipf("%s is not set; skipping the database tests", EnvURL)
	}

	db, err := sqlx.Connect("postgres", url)
	if err != nil {
		t.Fatalf("connecting to %s: %v", EnvURL, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrateOnce.Do(func() {
		ctx := context.Background()
		// Serialised across the parallel test-package processes: goose takes
		// no lock of its own, and two racing CREATE TABLEs fail both.
		if _, err := db.ExecContext(ctx, `SELECT pg_advisory_lock(802634)`); err != nil {
			t.Fatalf("taking the migration lock: %v", err)
		}
		defer func() { _, _ = db.ExecContext(ctx, `SELECT pg_advisory_unlock(802634)`) }()
		if err := postgres.Migrate(ctx, db); err != nil {
			t.Fatalf("migrating the test database: %v", err)
		}
	})
	return db
}
