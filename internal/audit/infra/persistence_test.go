// Integration tests against a real PostgreSQL. The audit table is history;
// what matters is that every column round-trips exactly and nothing here can
// update or delete.
package infra_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/audit/entity"
	"github.com/kotsmile/keyway/internal/audit/infra"
	auditservice "github.com/kotsmile/keyway/internal/audit/service"
	"github.com/kotsmile/keyway/internal/postgres/pgtest"
	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
)

// aStore keys this test's rows away from every other run: the audit table is
// append-only and shared, so rows are never cleaned up, only ignored.
func aStore(t *testing.T) secretsentity.StoreID {
	t.Helper()
	return secretsentity.StoreID("test-" + uuid.NewString())
}

func TestAnEntryRoundTripsThroughItsRow(t *testing.T) {
	repo := infra.NewPostgresAuditRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)
	secretID := uuid.New()

	record := entity.NewRecord(entity.Reveal, secretID, store, "db-creds").
		WithVersion("3").
		WithKeys([]string{"db_password"}).
		WithSubject("group:SRE").
		WithNote("incident 42")
	require.NoError(t, repo.Append(ctx, "alice", "7f3a9c2e", record))

	got, err := repo.ForSecret(ctx, store, "db-creds", 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	entry := got[0]
	assert.Positive(t, entry.ID)
	assert.False(t, entry.At.IsZero())
	assert.Equal(t, "alice", entry.Actor)
	assert.Equal(t, "7f3a9c2e", entry.ViaToken)
	assert.Equal(t, entity.Reveal, entry.Action)
	assert.Equal(t, store, entry.Store)
	assert.Equal(t, secretsentity.SecretName("db-creds"), entry.Secret)
	require.NotNil(t, entry.SecretID)
	assert.Equal(t, secretID, *entry.SecretID)
	assert.Equal(t, secretsentity.VersionID("3"), entry.Version)
	assert.Equal(t, []string{"db_password"}, entry.Keys)
	assert.Equal(t, "group:SRE", entry.Subject)
	assert.Equal(t, "incident 42", entry.Note)
}

func TestABrowserSessionStoresANullToken(t *testing.T) {
	// "" from the service must land as NULL, the way the Rust Option did —
	// the dashboard tells the two apart by the column being absent.
	db := pgtest.DB(t)
	repo := infra.NewPostgresAuditRepo(db)
	ctx := context.Background()
	store := aStore(t)

	require.NoError(t, repo.Append(ctx, "alice", "",
		entity.NewRecord(entity.Create, uuid.New(), store, "db-creds")))

	var isNull bool
	require.NoError(t, db.GetContext(ctx, &isNull,
		`SELECT via_token IS NULL FROM audit WHERE store = $1`, store))
	assert.True(t, isNull)

	got, err := repo.ForSecret(ctx, store, "db-creds", 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].ViaToken)
}

func TestTheEntryJSONShapeIsPinned(t *testing.T) {
	// The wire shape the Rust serde attributes produced, read back through
	// the row: empty optionals are ABSENT, not null and not "" (ADR-0005's
	// audit log is what the dashboard renders; ADR-0006 keeps its wire).
	repo := infra.NewPostgresAuditRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	require.NoError(t, repo.Append(ctx, "alice", "",
		entity.NewRecord(entity.Delete, uuid.New(), store, "db-creds")))
	got, err := repo.ForSecret(ctx, store, "db-creds", 1)
	require.NoError(t, err)
	require.Len(t, got, 1)

	raw, err := json.Marshal(got[0])
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(raw, &asMap))
	for _, present := range []string{"id", "at", "actor", "action", "store", "secret", "secret_id"} {
		assert.Contains(t, asMap, present)
	}
	for _, absent := range []string{"via_token", "version", "keys", "subject", "note"} {
		assert.NotContains(t, asMap, absent, "an unset %s is skipped, as serde skipped it", absent)
	}
}

func TestALegacyRowWithoutASecretIDStillReads(t *testing.T) {
	// Entries recorded before migration 0003 honestly do not know their uuid.
	db := pgtest.DB(t)
	repo := infra.NewPostgresAuditRepo(db)
	ctx := context.Background()
	store := aStore(t)

	// Written the way the Rust server before 0003 wrote it: no secret_id.
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit (actor, via_token, action, store, secret) VALUES ($1, NULL, 'create', $2, $3)`,
		"alice", store, "db-creds")
	require.NoError(t, err)

	got, err := repo.ForSecret(ctx, store, "db-creds", 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].SecretID)
	assert.Equal(t, entity.Create, got[0].Action)
}

func TestTheFeedPagesNewestFirstThroughBefore(t *testing.T) {
	repo := infra.NewPostgresAuditRepo(pgtest.DB(t))
	ctx := context.Background()
	store := aStore(t)

	for _, secret := range []secretsentity.SecretName{"one", "two", "three"} {
		require.NoError(t, repo.Append(ctx, "alice", "",
			entity.NewRecord(entity.Update, uuid.New(), store, secret)))
	}

	// The database is shared, so page with a limit big enough to hold
	// everybody's rows and judge only our own ordering.
	const pageSize = 500
	var mine []entity.Entry
	var before *int64
	for len(mine) < 3 {
		page, err := repo.Feed(ctx, pageSize, before)
		require.NoError(t, err)
		require.NotEmpty(t, page, "the feed ran out before our rows appeared")
		for _, entry := range page {
			if entry.Store == store {
				mine = append(mine, entry)
			}
		}
		last := page[len(page)-1].ID
		before = &last
	}

	require.Len(t, mine, 3)
	assert.Equal(t, secretsentity.SecretName("three"), mine[0].Secret, "newest first")
	assert.Equal(t, secretsentity.SecretName("two"), mine[1].Secret)
	assert.Equal(t, secretsentity.SecretName("one"), mine[2].Secret)
	assert.Greater(t, mine[0].ID, mine[1].ID)
}

func TestTheServiceTakesActorAndTokenFromTheSamePlace(t *testing.T) {
	// The reason Service.Record exists: a caller cannot record a reveal as
	// somebody else by passing the wrong string.
	repo := infra.NewPostgresAuditRepo(pgtest.DB(t))
	service := auditservice.NewService(repo)
	ctx := context.Background()
	store := aStore(t)

	require.NoError(t, service.Record(ctx, tokenActor{},
		entity.NewRecord(entity.Reveal, uuid.New(), store, "db-creds")))

	got, err := service.ForSecret(ctx, store, "db-creds", 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "alice", got[0].Actor)
	assert.Equal(t, "7f3a9c2e", got[0].ViaToken)
}

type tokenActor struct{}

func (tokenActor) Handle() string          { return "alice" }
func (tokenActor) TokenID() (string, bool) { return "7f3a9c2e", true }
