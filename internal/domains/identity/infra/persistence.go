// Package infra is where identity comes from.
package infra

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/kotsmile/keyway/internal/domains/identity/entity"
)

// PostgresIdentityRepo is what keyway remembers about a person between
// sign-ins.
//
// An API token carries no claim, so without this it could not know which
// groups its holder is in — and a grant to a team would be invisible to
// every bot and every CI job (ADR-0004).
//
// Remembered, not frozen: every sign-in refreshes it. Minting a token goes
// through a browser session, so a token's remembered groups are never empty.
type PostgresIdentityRepo struct {
	db *sqlx.DB
}

// NewPostgresIdentityRepo builds the repo over the pool.
func NewPostgresIdentityRepo(db *sqlx.DB) *PostgresIdentityRepo {
	return &PostgresIdentityRepo{db: db}
}

// Remember records a sign-in.
func (r *PostgresIdentityRepo) Remember(ctx context.Context, user *entity.RememberedUser) error {
	groups := user.Groups
	if groups == nil {
		// The column is NOT NULL and the Rust server could never write NULL
		// here; a nil slice must land as '{}', not as NULL.
		groups = []string{}
	}
	// Groups are REPLACED rather than merged. A person removed from a team
	// must lose it on their next sign-in; a merge would mean membership only
	// ever grew.
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (handle, groups, email, name, last_login)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (handle) DO UPDATE SET
		     groups = EXCLUDED.groups,
		     email = EXCLUDED.email,
		     name = EXCLUDED.name,
		     last_login = EXCLUDED.last_login`,
		user.Handle, pq.Array(groups), user.Email, user.Name, user.LastLogin)
	if err != nil {
		return fmt.Errorf("remembering a sign-in: %w", err)
	}
	return nil
}

// Recall is what was remembered, or nil if they have never signed in.
func (r *PostgresIdentityRepo) Recall(ctx context.Context, handle string) (*entity.RememberedUser, error) {
	user := entity.RememberedUser{Handle: handle}
	err := r.db.QueryRowContext(ctx,
		`SELECT groups, email, name, last_login FROM users WHERE handle = $1`,
		handle,
	).Scan(pq.Array(&user.Groups), &user.Email, &user.Name, &user.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("recalling a user: %w", err)
	}
	return &user, nil
}
