// Integration tests against a real PostgreSQL — including the cutover test:
// a row written the way the Rust server wrote it must verify through the Go
// service.
package infra_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/postgres/pgtest"
	"github.com/kotsmile/keyway/internal/tokens/entity"
	"github.com/kotsmile/keyway/internal/tokens/infra"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
)

// aSubject keys this test's rows away from every other run sharing the
// database.
func aSubject(t *testing.T) string {
	t.Helper()
	return "subject-" + uuid.NewString()
}

func TestARustMintedRowVerifiesThroughTheGoService(t *testing.T) {
	// THE cutover test (ADR-0006). The row is inserted exactly as the Rust
	// server's INSERT wrote it — id, sha256 hash, subject, name — with the
	// golden vector minted by the Rust minting code run with fixed bytes.
	// Verify must resolve the golden plaintext to the subject.
	db := pgtest.DB(t)
	ctx := context.Background()
	subject := aSubject(t)

	const goldenPlaintext = "kw-00112233aabbccdd-----____AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk"
	goldenHash, err := hex.DecodeString("e07767391987b5b8e95606b3cf66afd95be131c09e4c006bf81e0961e33eb333")
	require.NoError(t, err)

	// The id column is the token id, unique across runs; re-runs must clear
	// their own golden row first since the id half is pinned.
	_, err = db.ExecContext(ctx, `DELETE FROM tokens WHERE id = $1`, "00112233aabbccdd")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx,
		`INSERT INTO tokens (id, hash, subject, name, expires_at) VALUES ($1, $2, $3, $4, NULL)`,
		"00112233aabbccdd", goldenHash, subject, "eso — payment-bot prod")
	require.NoError(t, err)

	service := tokensservice.NewService(infra.NewPostgresTokenRepo(db))
	token, err := service.Verify(ctx, goldenPlaintext, time.Now())
	require.NoError(t, err, "a Rust-minted token must keep working across the cutover")
	assert.Equal(t, subject, token.Subject)
	assert.Equal(t, entity.Name("eso — payment-bot prod"), token.Name)
}

func TestMintVerifyListRevoke(t *testing.T) {
	// The whole life of a token, through the service against the real table.
	db := pgtest.DB(t)
	ctx := context.Background()
	subject := aSubject(t)
	service := tokensservice.NewService(infra.NewPostgresTokenRepo(db))

	minted, err := service.Mint(ctx, subject, entity.Name("eso prod"), nil)
	require.NoError(t, err)
	assert.False(t, minted.Token.CreatedAt.IsZero(), "created_at is storage's answer")

	verified, err := service.Verify(ctx, minted.Plaintext.Expose(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, subject, verified.Subject)

	// Verify touched last_used, best-effort.
	listed, err := service.List(ctx, subject)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.NotNil(t, listed[0].LastUsed)

	revoked, err := service.Revoke(ctx, subject, minted.Token.ID)
	require.NoError(t, err)
	assert.True(t, revoked)

	_, err = service.Verify(ctx, minted.Plaintext.Expose(), time.Now())
	assert.ErrorIs(t, err, entity.Unknown, "a revoked token is gone outright")
}

func TestAWrongSecretIsRejectedWithoutTouching(t *testing.T) {
	db := pgtest.DB(t)
	ctx := context.Background()
	subject := aSubject(t)
	service := tokensservice.NewService(infra.NewPostgresTokenRepo(db))

	minted, err := service.Mint(ctx, subject, entity.Name("eso prod"), nil)
	require.NoError(t, err)

	_, err = service.Verify(ctx, "kw-"+minted.Token.ID.String()+"-not-the-secret", time.Now())
	assert.ErrorIs(t, err, entity.WrongSecret)

	listed, err := service.List(ctx, subject)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Nil(t, listed[0].LastUsed, "a refused presentation is not a use")
}

func TestListingIsNewestFirst(t *testing.T) {
	db := pgtest.DB(t)
	ctx := context.Background()
	subject := aSubject(t)
	repo := infra.NewPostgresTokenRepo(db)
	service := tokensservice.NewService(repo)

	first, err := service.Mint(ctx, subject, entity.Name("older"), nil)
	require.NoError(t, err)
	second, err := service.Mint(ctx, subject, entity.Name("newer"), nil)
	require.NoError(t, err)
	// created_at comes from now() with microsecond precision; two inserts in
	// one transaction-less burst can tie, so order the tie away.
	_, err = db.ExecContext(ctx,
		`UPDATE tokens SET created_at = created_at + interval '1 second' WHERE id = $1`,
		second.Token.ID)
	require.NoError(t, err)

	listed, err := service.List(ctx, subject)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.Equal(t, second.Token.ID, listed[0].ID)
	assert.Equal(t, first.Token.ID, listed[1].ID)
}

func TestRevokeIsScopedToTheSubject(t *testing.T) {
	// Deleting somebody else's token by id must not work, and must be
	// indistinguishable from the token not existing.
	db := pgtest.DB(t)
	ctx := context.Background()
	service := tokensservice.NewService(infra.NewPostgresTokenRepo(db))

	owner := aSubject(t)
	minted, err := service.Mint(ctx, owner, "mine", nil)
	require.NoError(t, err)

	revoked, err := service.Revoke(ctx, aSubject(t), minted.Token.ID)
	require.NoError(t, err)
	assert.False(t, revoked)

	_, err = service.Verify(ctx, minted.Plaintext.Expose(), time.Now())
	assert.NoError(t, err, "the token still works for its owner")
}

func TestAnExpiredRowIsRefusedButKept(t *testing.T) {
	db := pgtest.DB(t)
	ctx := context.Background()
	subject := aSubject(t)
	service := tokensservice.NewService(infra.NewPostgresTokenRepo(db))

	expiry := time.Now().UTC().Add(time.Hour)
	minted, err := service.Mint(ctx, subject, entity.Name("short-lived"), &expiry)
	require.NoError(t, err)

	_, err = service.Verify(ctx, minted.Plaintext.Expose(), expiry.Add(time.Second))
	assert.ErrorIs(t, err, entity.Expired)

	listed, err := service.List(ctx, subject)
	require.NoError(t, err)
	assert.Len(t, listed, 1, "expiry refuses, it does not delete")
}
