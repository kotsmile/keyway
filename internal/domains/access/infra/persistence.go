// Package infra is rows for grants and ownership.
//
// Translation only. Which grant opens what is a rule, and it lives in
// entity.Resolve — note that nothing here filters by who is asking, because a
// caller-filtered query would put half the authorisation rule in SQL.
package infra

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/kotsmile/keyway/internal/domains/access"
	"github.com/kotsmile/keyway/internal/domains/access/entity"
)

// PostgresAccessRepo stores grants and ownership in keyway's own database.
type PostgresAccessRepo struct {
	db *sqlx.DB
}

var _ access.Repo = (*PostgresAccessRepo)(nil)

// NewPostgresAccessRepo wires the repo to the pool.
func NewPostgresAccessRepo(db *sqlx.DB) *PostgresAccessRepo {
	return &PostgresAccessRepo{db: db}
}

type delegationDTO struct {
	ID          uuid.UUID      `db:"id"`
	Store       string         `db:"store"`
	Secret      string         `db:"secret"`
	SubjectKind string         `db:"subject_kind"`
	SubjectID   string         `db:"subject_id"`
	Level       string         `db:"level"`
	Keys        pq.StringArray `db:"keys"`
	GrantedBy   string         `db:"granted_by"`
	GrantedAt   time.Time      `db:"granted_at"`
	ExpiresAt   *time.Time     `db:"expires_at"`
	Note        string         `db:"note"`
}

func (dto delegationDTO) delegation() (entity.Delegation, error) {
	var subject entity.Subject
	switch dto.SubjectKind {
	case "user":
		subject = entity.User(dto.SubjectID)
	case "group":
		subject = entity.Group(dto.SubjectID)
	default:
		return entity.Delegation{}, fmt.Errorf("unknown subject kind %q", dto.SubjectKind)
	}
	level, err := entity.ParseLevel(dto.Level)
	if err != nil {
		return entity.Delegation{}, err
	}
	return entity.Delegation{
		ID:        dto.ID,
		Store:     dto.Store,
		Secret:    dto.Secret,
		Subject:   subject,
		Level:     level,
		Keys:      dto.Keys,
		GrantedBy: dto.GrantedBy,
		GrantedAt: dto.GrantedAt,
		ExpiresAt: dto.ExpiresAt,
		Note:      dto.Note,
	}, nil
}

func delegations(dtos []delegationDTO) ([]entity.Delegation, error) {
	out := make([]entity.Delegation, 0, len(dtos))
	for _, dto := range dtos {
		grant, err := dto.delegation()
		if err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, nil
}

// textArray never writes NULL for an absent key list: the column is NOT NULL
// and the Rust side always wrote '{}', so an empty grant scope stays an empty
// array on disk.
func textArray(keys []string) pq.StringArray {
	if keys == nil {
		return pq.StringArray{}
	}
	return keys
}

type ownershipDTO struct {
	Store  string    `db:"store"`
	Secret string    `db:"secret"`
	Owner  string    `db:"owner"`
	Since  time.Time `db:"since"`
}

// GrantsOn reads every grant on one secret.
func (r *PostgresAccessRepo) GrantsOn(ctx context.Context, store, secret string) ([]entity.Delegation, error) {
	var rows []delegationDTO
	err := r.db.SelectContext(ctx, &rows,
		`SELECT id, store, secret, subject_kind, subject_id, level, keys,
		        granted_by, granted_at, expires_at, note
		 FROM delegations WHERE store = $1 AND secret = $2
		 ORDER BY granted_at`,
		store, secret)
	if err != nil {
		return nil, fmt.Errorf("reading grants on a secret: %w", err)
	}
	return delegations(rows)
}

// OwnerOf reads who owns a secret, when anybody does.
func (r *PostgresAccessRepo) OwnerOf(ctx context.Context, store, secret string) (*entity.Ownership, error) {
	var row ownershipDTO
	err := r.db.GetContext(ctx, &row,
		`SELECT store, secret, owner, since FROM ownership
		 WHERE store = $1 AND secret = $2`,
		store, secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading a secret's owner: %w", err)
	}
	return &entity.Ownership{Store: row.Store, Secret: row.Secret, Owner: row.Owner, Since: row.Since}, nil
}

// GrantsForSubjects reads every grant addressed to any of `subjects`.
func (r *PostgresAccessRepo) GrantsForSubjects(ctx context.Context, subjects []entity.Subject) ([]entity.Delegation, error) {
	// Two arrays rather than a tuple IN, so the kind cannot be matched
	// against the wrong name.
	kinds := make([]string, 0, len(subjects))
	ids := make([]string, 0, len(subjects))
	for _, s := range subjects {
		kinds = append(kinds, s.Kind())
		ids = append(ids, s.ID())
	}

	var rows []delegationDTO
	err := r.db.SelectContext(ctx, &rows,
		`SELECT id, store, secret, subject_kind, subject_id, level, keys,
		        granted_by, granted_at, expires_at, note
		 FROM delegations d
		 WHERE EXISTS (
		     SELECT 1 FROM unnest($1::text[], $2::text[]) AS want(kind, id)
		     WHERE want.kind = d.subject_kind AND want.id = d.subject_id
		 )
		 ORDER BY d.store, d.secret`,
		pq.Array(kinds), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("reading grants for a caller: %w", err)
	}
	return delegations(rows)
}

// SaveGrant writes a grant, replacing what the same subject already held on
// the same secret.
func (r *PostgresAccessRepo) SaveGrant(ctx context.Context, grant entity.Delegation) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO delegations
		    (id, store, secret, subject_kind, subject_id, level, keys,
		     granted_by, granted_at, expires_at, note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (store, secret, subject_kind, subject_id) DO UPDATE SET
		     level = EXCLUDED.level,
		     keys = EXCLUDED.keys,
		     granted_by = EXCLUDED.granted_by,
		     granted_at = EXCLUDED.granted_at,
		     expires_at = EXCLUDED.expires_at,
		     note = EXCLUDED.note`,
		grant.ID, grant.Store, grant.Secret, grant.Subject.Kind(), grant.Subject.ID(),
		grant.Level.String(), textArray(grant.Keys), grant.GrantedBy, grant.GrantedAt,
		grant.ExpiresAt, grant.Note)
	if err != nil {
		return fmt.Errorf("writing a grant: %w", err)
	}
	return nil
}

// RemoveGrant revokes a grant, reporting whether there was one.
func (r *PostgresAccessRepo) RemoveGrant(ctx context.Context, id uuid.UUID) (bool, error) {
	done, err := r.db.ExecContext(ctx, `DELETE FROM delegations WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("revoking a grant: %w", err)
	}
	affected, err := done.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoking a grant: %w", err)
	}
	return affected > 0, nil
}

// SetOwner records who owns a secret.
//
// Replaces rather than adds: a transfer changes who is answerable, it does
// not produce a second owner.
func (r *PostgresAccessRepo) SetOwner(ctx context.Context, ownership entity.Ownership) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO ownership (store, secret, owner, since)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (store, secret) DO UPDATE SET
		     owner = EXCLUDED.owner,
		     since = EXCLUDED.since`,
		ownership.Store, ownership.Secret, ownership.Owner, ownership.Since)
	if err != nil {
		return fmt.Errorf("recording ownership: %w", err)
	}
	return nil
}
