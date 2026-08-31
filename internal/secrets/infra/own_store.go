// Package infra is the backends keyway aggregates. Translation only.
package infra

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/kotsmile/keyway/internal/secrets/entity"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
)

// PostgresOwnStoreRepo is rows for keyway's own Store.
//
// Translation only. Which version is current, what a destroyed one yields and
// how the next number is chosen are rules, and they live in the entity
// package.
type PostgresOwnStoreRepo struct {
	db *sqlx.DB
}

// NewPostgresOwnStoreRepo mounts the repo over a pool.
func NewPostgresOwnStoreRepo(db *sqlx.DB) *PostgresOwnStoreRepo {
	return &PostgresOwnStoreRepo{db: db}
}

// secretRow is a secret row, joined to its newest readable version.
type secretRow struct {
	Store         string        `db:"store"`
	Name          string        `db:"name"`
	Labels        []byte        `db:"labels"`
	Annotations   []byte        `db:"annotations"`
	LatestVersion sql.NullInt64 `db:"latest_version"`
}

func (r secretRow) secret() (entity.Secret, error) {
	secret := entity.Secret{
		Store: entity.StoreID(r.Store),
		Name:  entity.SecretName(r.Name),
	}
	if err := json.Unmarshal(r.Labels, &secret.Labels); err != nil {
		return entity.Secret{}, fmt.Errorf("reading labels: %w", err)
	}
	if err := json.Unmarshal(r.Annotations, &secret.Annotations); err != nil {
		return entity.Secret{}, fmt.Errorf("reading annotations: %w", err)
	}
	if r.LatestVersion.Valid {
		secret.LatestVersion = entity.NumberVersion(r.LatestVersion.Int64)
	}
	return secret, nil
}

// versionRow is a version row.
type versionRow struct {
	Store      string `db:"store"`
	Name       string `db:"name"`
	Version    int64  `db:"version"`
	Ciphertext []byte `db:"ciphertext"`
	Nonce      []byte `db:"nonce"`
	KeyID      string `db:"key_id"`
	State      string `db:"state"`
}

func (r versionRow) ownVersion() entity.OwnVersion {
	return entity.OwnVersion{
		Store:  entity.StoreID(r.Store),
		Secret: entity.SecretName(r.Name),
		Number: r.Version,
		Sealed: entity.Sealed{
			KeyID:      r.KeyID,
			Nonce:      r.Nonce,
			Ciphertext: r.Ciphertext,
		},
		State: entity.ParseVersionState(r.State),
	}
}

const secretColumns = `SELECT s.store, s.name,
	       s.labels,
	       s.annotations,
	       (SELECT v.version FROM own_versions v
	         WHERE v.store = s.store AND v.name = s.name AND v.state = 'enabled'
	         ORDER BY v.version DESC LIMIT 1) as latest_version
	  FROM own_secrets s`

// ListSecrets implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) ListSecrets(ctx context.Context, store entity.StoreID) ([]entity.Secret, error) {
	var rows []secretRow
	err := r.db.SelectContext(ctx, &rows, secretColumns+` WHERE s.store = $1 ORDER BY s.name`, store.String())
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}
	out := make([]entity.Secret, 0, len(rows))
	for _, row := range rows {
		secret, err := row.secret()
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}
		out = append(out, secret)
	}
	return out, nil
}

// GetSecret implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) GetSecret(
	ctx context.Context, store entity.StoreID, name entity.SecretName,
) (*entity.Secret, error) {
	var row secretRow
	err := r.db.GetContext(ctx, &row,
		secretColumns+` WHERE s.store = $1 AND s.name = $2`, store.String(), name.String())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading a secret: %w", err)
	}
	secret, err := row.secret()
	if err != nil {
		return nil, fmt.Errorf("reading a secret: %w", err)
	}
	return &secret, nil
}

// InsertSecret implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) InsertSecret(ctx context.Context, secret entity.Secret) error {
	labels, err := marshalMetadata(secret.Labels)
	if err != nil {
		return fmt.Errorf("creating a secret: %w", err)
	}
	annotations, err := marshalMetadata(secret.Annotations)
	if err != nil {
		return fmt.Errorf("creating a secret: %w", err)
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO own_secrets (store, name, labels, annotations)
		 VALUES ($1, $2, $3, $4)`,
		secret.Store.String(), secret.Name.String(), labels, annotations)
	if err != nil {
		return fmt.Errorf("creating a secret: %w", err)
	}
	return nil
}

// UpdateLabels implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) UpdateLabels(
	ctx context.Context, store entity.StoreID, name entity.SecretName, labels entity.Metadata,
) (bool, error) {
	encoded, err := marshalMetadata(labels)
	if err != nil {
		return false, fmt.Errorf("setting labels: %w", err)
	}
	done, err := r.db.ExecContext(ctx,
		`UPDATE own_secrets SET labels = $3 WHERE store = $1 AND name = $2`,
		store.String(), name.String(), encoded)
	if err != nil {
		return false, fmt.Errorf("setting labels: %w", err)
	}
	affected, err := done.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("setting labels: %w", err)
	}
	return affected > 0, nil
}

// DeleteSecret implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) DeleteSecret(
	ctx context.Context, store entity.StoreID, name entity.SecretName,
) (bool, error) {
	done, err := r.db.ExecContext(ctx,
		`DELETE FROM own_secrets WHERE store = $1 AND name = $2`, store.String(), name.String())
	if err != nil {
		return false, fmt.Errorf("deleting a secret: %w", err)
	}
	affected, err := done.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("deleting a secret: %w", err)
	}
	return affected > 0, nil
}

// ListVersions implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) ListVersions(
	ctx context.Context, store entity.StoreID, name entity.SecretName,
) ([]entity.Version, error) {
	var rows []struct {
		Version int64  `db:"version"`
		State   string `db:"state"`
	}
	err := r.db.SelectContext(ctx, &rows,
		`SELECT version, state FROM own_versions
		 WHERE store = $1 AND name = $2 ORDER BY version DESC`,
		store.String(), name.String())
	if err != nil {
		return nil, fmt.Errorf("listing versions: %w", err)
	}
	out := make([]entity.Version, 0, len(rows))
	for _, row := range rows {
		out = append(out, entity.Version{
			ID:    entity.NumberVersion(row.Version),
			State: entity.ParseVersionState(row.State),
		})
	}
	return out, nil
}

// GetVersion implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) GetVersion(
	ctx context.Context, store entity.StoreID, name entity.SecretName, number int64,
) (*entity.OwnVersion, error) {
	var row versionRow
	err := r.db.GetContext(ctx, &row,
		`SELECT store, name, version, ciphertext, nonce, key_id, state
		 FROM own_versions WHERE store = $1 AND name = $2 AND version = $3`,
		store.String(), name.String(), number)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading a version: %w", err)
	}
	version := row.ownVersion()
	return &version, nil
}

// AppendVersion implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) AppendVersion(
	ctx context.Context, store entity.StoreID, name entity.SecretName, seal secretsservice.SealWith,
) (entity.OwnVersion, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return entity.OwnVersion{}, fmt.Errorf("starting a transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a rollback after commit is a no-op

	// Locking the secret row is what serialises two concurrent writers. The
	// number is bound into the seal, so allocating it outside this
	// transaction would let them seal different payloads under one number.
	var locked []string
	if err := tx.SelectContext(ctx, &locked,
		`SELECT store FROM own_secrets WHERE store = $1 AND name = $2 FOR UPDATE`,
		store.String(), name.String()); err != nil {
		return entity.OwnVersion{}, fmt.Errorf("locking a secret: %w", err)
	}

	var highest int64
	if err := tx.GetContext(ctx, &highest,
		`SELECT coalesce(max(version), 0) FROM own_versions
		 WHERE store = $1 AND name = $2`,
		store.String(), name.String()); err != nil {
		return entity.OwnVersion{}, fmt.Errorf("allocating a version: %w", err)
	}

	version, err := seal(highest + 1)
	if err != nil {
		return entity.OwnVersion{}, err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO own_versions (store, name, version, ciphertext, nonce, key_id, state)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		version.Store.String(), version.Secret.String(), version.Number,
		version.Sealed.Ciphertext, version.Sealed.Nonce, version.Sealed.KeyID,
		version.State.Word()); err != nil {
		return entity.OwnVersion{}, fmt.Errorf("writing a version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return entity.OwnVersion{}, fmt.Errorf("committing a version: %w", err)
	}
	return version, nil
}

// KeyIDsInUse implements secretsservice.OwnStoreRepo.
func (r *PostgresOwnStoreRepo) KeyIDsInUse(ctx context.Context, store entity.StoreID) ([]string, error) {
	var ids []string
	err := r.db.SelectContext(ctx, &ids,
		`SELECT DISTINCT key_id FROM own_versions
		 WHERE store = $1 AND state <> 'destroyed' ORDER BY key_id`,
		store.String())
	if err != nil {
		return nil, fmt.Errorf("listing keys in use: %w", err)
	}
	return ids, nil
}

// marshalMetadata writes a nil map as the `{}` the columns default to, the
// same JSON the Rust server wrote.
func marshalMetadata(m entity.Metadata) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

var _ secretsservice.OwnStoreRepo = (*PostgresOwnStoreRepo)(nil)
