// Package postgres is the database keyway owns.
//
// What lives here is what a secret manager cannot answer: who owns a secret,
// who may see it, and who looked. Payloads do not, except in keyway's own
// Store — see the keyway SecretManager implementation, the one backend where
// keyway holds a value at all.
package postgres

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"

	keyway "github.com/kotsmile/keyway"
	"github.com/kotsmile/keyway/config"
)

// Connect opens the pool.
func Connect(ctx context.Context, cfg config.Postgres) (*sqlx.DB, error) {
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("the postgres address %q is not host:port", cfg.Addr)
	}
	dsn := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.User, cfg.Password),
		Host:     net.JoinHostPort(host, port),
		Path:     "/" + cfg.Name,
		RawQuery: url.Values{"sslmode": {cfg.SSLMode}}.Encode(),
	}
	db, err := sqlx.ConnectContext(ctx, "postgres", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres at %s: %w", cfg.Addr, err)
	}
	db.SetMaxOpenConns(cfg.MaxConn)
	return db, nil
}

// Migrate brings the schema up to date.
//
// Run as its own command rather than on every boot: a rolling deploy with
// three replicas racing to migrate is a deploy that fails in a way nobody can
// reproduce.
func Migrate(ctx context.Context, db *sqlx.DB) error {
	goose.SetBaseFS(keyway.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	if err := adoptSqlxHistory(ctx, db); err != nil {
		return fmt.Errorf("adopting the sqlx migration history: %w", err)
	}
	if err := goose.UpContext(ctx, db.DB, "migrations"); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

// adoptSqlxHistory makes goose agree with what the Rust server already
// applied.
//
// A database the Rust server migrated has the schema but no goose history —
// sqlx recorded it in _sqlx_migrations. Re-running those files would fail on
// the first CREATE TABLE, so the sqlx history is copied into goose's version
// table once, before goose looks. The version numbers line up because the
// files are the same files under the same numeric prefixes.
func adoptSqlxHistory(ctx context.Context, db *sqlx.DB) error {
	var hasSqlx bool
	if err := db.GetContext(ctx, &hasSqlx, `SELECT to_regclass('_sqlx_migrations') IS NOT NULL`); err != nil {
		return err
	}
	if !hasSqlx {
		return nil
	}
	// GetDBVersion also creates goose's table when missing; a non-zero
	// version means goose has run here before and the history is not ours to
	// rewrite.
	current, err := goose.GetDBVersionContext(ctx, db.DB)
	if err != nil {
		return err
	}
	if current != 0 {
		return nil
	}
	var versions []int64
	if err := db.SelectContext(ctx, &versions, `SELECT version FROM _sqlx_migrations ORDER BY version`); err != nil {
		return err
	}
	for _, version := range versions {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)`, version); err != nil {
			return err
		}
	}
	return nil
}
