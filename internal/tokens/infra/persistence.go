// Package infra is rows for issued tokensservice.
//
// Translation only. What makes a presented token acceptable is a rule, and it
// lives in the entity package.
package infra

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/kotsmile/keyway/internal/tokens/entity"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
)

// PostgresTokenRepo stores issued tokens in keyway's own database.
type PostgresTokenRepo struct {
	db *sqlx.DB
}

var _ tokensservice.Repo = (*PostgresTokenRepo)(nil)

// NewPostgresTokenRepo wires the repo to the pool.
func NewPostgresTokenRepo(db *sqlx.DB) *PostgresTokenRepo {
	return &PostgresTokenRepo{db: db}
}

// tokenDTO is a row. The columns stay plain strings and the entity types are
// put on and taken off here, which is what makes this package translation:
// nothing but the driver's own vocabulary crosses into a query.
type tokenDTO struct {
	ID        string     `db:"id"`
	Hash      []byte     `db:"hash"`
	Subject   string     `db:"subject"`
	Name      string     `db:"name"`
	CreatedAt time.Time  `db:"created_at"`
	ExpiresAt *time.Time `db:"expires_at"`
	LastUsed  *time.Time `db:"last_used"`
}

// Insert writes the row and reports when storage says it was written.
func (r *PostgresTokenRepo) Insert(ctx context.Context, token entity.StoredToken) (time.Time, error) {
	var createdAt time.Time
	err := r.db.GetContext(ctx, &createdAt,
		`INSERT INTO tokens (id, hash, subject, name, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING created_at`,
		token.ID.String(), token.Hash, token.Subject, token.Name.String(), token.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("minting a token: %w", err)
	}
	return createdAt, nil
}

// ByID looks a token up by its public half.
func (r *PostgresTokenRepo) ByID(ctx context.Context, id entity.ID) (*entity.StoredToken, error) {
	var row tokenDTO
	err := r.db.GetContext(ctx, &row,
		`SELECT id, hash, subject, name, created_at, expires_at, last_used
		 FROM tokens WHERE id = $1`, id.String())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up a token: %w", err)
	}
	return &entity.StoredToken{
		ID:        entity.ID(row.ID),
		Hash:      row.Hash,
		Subject:   row.Subject,
		Name:      entity.Name(row.Name),
		CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt,
		LastUsed:  row.LastUsed,
	}, nil
}

// ForSubject lists a subject's tokens, newest first.
func (r *PostgresTokenRepo) ForSubject(ctx context.Context, subject string) ([]entity.Token, error) {
	var rows []struct {
		ID        string     `db:"id"`
		Name      string     `db:"name"`
		CreatedAt time.Time  `db:"created_at"`
		ExpiresAt *time.Time `db:"expires_at"`
		LastUsed  *time.Time `db:"last_used"`
	}
	err := r.db.SelectContext(ctx, &rows,
		`SELECT id, name, created_at, expires_at, last_used
		 FROM tokens WHERE subject = $1 ORDER BY created_at DESC`, subject)
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}
	out := make([]entity.Token, 0, len(rows))
	for _, row := range rows {
		out = append(out, entity.Token{
			ID:        entity.ID(row.ID),
			Subject:   subject,
			Name:      entity.Name(row.Name),
			CreatedAt: row.CreatedAt,
			ExpiresAt: row.ExpiresAt,
			LastUsed:  row.LastUsed,
		})
	}
	return out, nil
}

// Delete revokes one of `subject`'s tokensservice.
//
// Scoped to the subject in the statement rather than in a check before it, so
// there is no window between deciding and doing.
func (r *PostgresTokenRepo) Delete(ctx context.Context, subject string, id entity.ID) (bool, error) {
	done, err := r.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE subject = $1 AND id = $2`, subject, id.String())
	if err != nil {
		return false, fmt.Errorf("revoking a token: %w", err)
	}
	affected, err := done.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoking a token: %w", err)
	}
	return affected > 0, nil
}

// Touch records when a token was last presented.
//
// Best-effort by construction: the result is discarded. "Last used" is a
// convenience for the person deciding whether a token is still needed, never
// an authorisation input.
func (r *PostgresTokenRepo) Touch(ctx context.Context, id entity.ID, at time.Time) {
	_, _ = r.db.ExecContext(ctx, `UPDATE tokens SET last_used = $2 WHERE id = $1`, id.String(), at)
}
