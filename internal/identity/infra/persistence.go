// Package infra is where identity comes from.
package infra

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/kotsmile/keyway/internal/identity/entity"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
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
	// The column is NOT NULL and the Rust server could never write NULL here;
	// a nil slice must land as '{}', not as NULL. GroupWords never returns
	// nil, so this holds by construction.
	groups := entity.GroupWords(user.Groups)
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
		user.Handle.String(), pq.Array(groups), user.Email, user.Name, user.LastLogin)
	if err != nil {
		return fmt.Errorf("remembering a sign-in: %w", err)
	}
	return nil
}

// Recall is what was remembered, or nil if they have never signed in.
func (r *PostgresIdentityRepo) Recall(
	ctx context.Context, handle entity.Handle,
) (*entity.RememberedUser, error) {
	user := entity.RememberedUser{Handle: handle}
	// The column holds text; the group names are put back on here, which is
	// this package's whole job. A row written before a name was required
	// could carry an empty entry, and dropping it is the same reading the
	// claim edge gives one.
	var groups []string
	err := r.db.QueryRowContext(ctx,
		`SELECT groups, email, name, last_login FROM users WHERE handle = $1`,
		handle.String(),
	).Scan(pq.Array(&groups), &user.Email, &user.Name, &user.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("recalling a user: %w", err)
	}
	user.Groups, _ = entity.GroupNamesOf(groups)
	return &user, nil
}

var _ identityservice.Repo = (*PostgresIdentityRepo)(nil)
