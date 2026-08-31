// Package infra is rows for the audit log.
//
// Translation only, and append-only: there is no update and no delete here.
package infra

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/kotsmile/keyway/internal/audit/entity"
	auditservice "github.com/kotsmile/keyway/internal/audit/service"
	secrets "github.com/kotsmile/keyway/internal/secrets/entity"
)

// PostgresAuditRepo stores the audit log in keyway's own database.
type PostgresAuditRepo struct {
	db *sqlx.DB
}

var _ auditservice.Repo = (*PostgresAuditRepo)(nil)

// NewPostgresAuditRepo wires the repo to the pool.
func NewPostgresAuditRepo(db *sqlx.DB) *PostgresAuditRepo {
	return &PostgresAuditRepo{db: db}
}

type entryDTO struct {
	ID       int64          `db:"id"`
	At       time.Time      `db:"at"`
	Actor    string         `db:"actor"`
	ViaToken sql.NullString `db:"via_token"`
	Action   string         `db:"action"`
	Store    string         `db:"store"`
	Secret   string         `db:"secret"`
	SecretID *uuid.UUID     `db:"secret_id"`
	Version  string         `db:"version"`
	Keys     pq.StringArray `db:"keys"`
	Subject  string         `db:"subject"`
	Note     string         `db:"note"`
}

func (dto entryDTO) entry() entity.Entry {
	return entity.Entry{
		ID:       dto.ID,
		At:       dto.At,
		Actor:    dto.Actor,
		ViaToken: dto.ViaToken.String,
		// The word is kept as it was stored, even one this build has no
		// constant for: the log is evidence, and evidence with gaps is worse
		// than evidence with an unfamiliar word in it. (The Rust port point:
		// its enum had to guess `update` here; the Go Action is a string and
		// need not guess.)
		Action:   entity.Action(dto.Action),
		Store:    secrets.StoreID(dto.Store),
		Secret:   secrets.SecretName(dto.Secret),
		SecretID: dto.SecretID,
		Version:  secrets.VersionID(dto.Version),
		Keys:     dto.Keys,
		Subject:  dto.Subject,
		Note:     dto.Note,
	}
}

func entries(dtos []entryDTO) []entity.Entry {
	out := make([]entity.Entry, 0, len(dtos))
	for _, dto := range dtos {
		out = append(out, dto.entry())
	}
	return out
}

// Append writes one entry. `at` and `id` are storage's to fill.
func (r *PostgresAuditRepo) Append(ctx context.Context, actor, viaToken string, record entity.Record) error {
	// "" means a browser session and is stored as NULL, matching the rows the
	// Rust server wrote for an absent token.
	via := sql.NullString{String: viaToken, Valid: viaToken != ""}
	keys := pq.StringArray(record.Keys)
	if keys == nil {
		keys = pq.StringArray{}
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit
		    (actor, via_token, action, store, secret, secret_id, version, keys, subject, note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		actor, via, string(record.Action), record.Store.String(), record.Secret.String(),
		record.SecretID, record.Version.String(), keys, record.Subject, record.Note)
	if err != nil {
		return fmt.Errorf("appending an audit entry: %w", err)
	}
	return nil
}

// ForSecret reads one secret's history, newest first.
func (r *PostgresAuditRepo) ForSecret(
	ctx context.Context, store secrets.StoreID, secret secrets.SecretName, limit int64,
) ([]entity.Entry, error) {
	var rows []entryDTO
	err := r.db.SelectContext(ctx, &rows,
		`SELECT id, at, actor, via_token, action, store, secret, secret_id, version, keys, subject, note
		 FROM audit WHERE store = $1 AND secret = $2
		 ORDER BY at DESC, id DESC LIMIT $3`,
		store.String(), secret.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("reading a secret's history: %w", err)
	}
	return entries(rows), nil
}

// Feed reads everything, newest first, before the cursor when one is given.
func (r *PostgresAuditRepo) Feed(ctx context.Context, limit int64, before *int64) ([]entity.Entry, error) {
	var rows []entryDTO
	err := r.db.SelectContext(ctx, &rows,
		`SELECT id, at, actor, via_token, action, store, secret, secret_id, version, keys, subject, note
		 FROM audit WHERE ($2::bigint IS NULL OR id < $2)
		 ORDER BY at DESC, id DESC LIMIT $1`,
		limit, before)
	if err != nil {
		return nil, fmt.Errorf("reading the audit feed: %w", err)
	}
	return entries(rows), nil
}
