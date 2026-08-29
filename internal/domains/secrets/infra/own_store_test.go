// keyway's own Store, against a real Postgres.
//
// Skipped unless KEYWAY_TEST_DATABASE_URL is set. This is the one backend
// where keyway holds a payload, so what these assert is that a value written
// here comes back, that nothing written here is readable from the table
// itself, and that rotating a key does not strand what came before it.

package infra

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/domains/secrets"
	"github.com/kotsmile/keyway/internal/domains/secrets/entity"
	"github.com/kotsmile/keyway/internal/infra/postgres"
)

// 32 bytes of base64, distinct so a test can tell which one opened a payload.
const (
	keyV1 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	keyV2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

// testPool is a migrated database per test.
//
// Each test gets a private schema rather than sharing `public`: one test's
// fixtures must not be another's mystery failure. The tests do not run in
// parallel — the migrator holds package-level state.
func testPool(t *testing.T) *sqlx.DB {
	t.Helper()
	raw := os.Getenv("KEYWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("KEYWAY_TEST_DATABASE_URL is unset")
	}

	schema := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin, err := sqlx.Connect("postgres", raw)
	require.NoError(t, err, "connect to test database")
	// Safe by construction: `schema` is `test_` plus generated hex, so there
	// is nothing in it a caller could have influenced.
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err, "create test schema")
	require.NoError(t, admin.Close())

	parsed, err := url.Parse(raw)
	require.NoError(t, err, "a valid connection url")
	query := parsed.Query()
	query.Set("options", "-csearch_path="+schema)
	parsed.RawQuery = query.Encode()

	db, err := sqlx.Connect("postgres", parsed.String())
	require.NoError(t, err, "connect to the test schema")
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = db.Close()
	})

	require.NoError(t, postgres.Migrate(context.Background(), db), "migrations apply")
	return db
}

func keyring(t *testing.T, active string, keys map[string]string) *entity.Keyring {
	t.Helper()
	ring, err := entity.NewKeyring(active, keys)
	require.NoError(t, err, "a valid keyring")
	return ring
}

func mountedOwn(t *testing.T, db *sqlx.DB, id, active string, keys map[string]string) *secrets.OwnStoreService {
	t.Helper()
	return secrets.NewOwnStoreService(id, NewPostgresOwnStoreRepo(db), keyring(t, active, keys))
}

func ownStore(t *testing.T, db *sqlx.DB, active string, keys map[string]string) *secrets.OwnStoreService {
	t.Helper()
	return mountedOwn(t, db, "local", active, keys)
}

func withSecret(t *testing.T, store *secrets.OwnStoreService, name string, payload []byte) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.Create(ctx, name, entity.Metadata{}), "create")
	_, err := store.AddVersion(ctx, name, payload)
	require.NoError(t, err, "add version")
}

func TestAValueWrittenComesBack(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})

	withSecret(t, store, "db-creds", []byte("hunter2"))

	got, err := store.Access(context.Background(), "db-creds", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), got)
}

func TestThePayloadIsNotReadableFromTheTable(t *testing.T) {
	// The property the whole package exists for. Anyone with SELECT on the
	// database — a backup, a replica, a support query — sees ciphertext.
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})

	withSecret(t, store, "db-creds", []byte("hunter2"))

	var ciphertext []byte
	require.NoError(t, db.Get(&ciphertext, "SELECT ciphertext FROM own_versions"))
	assert.NotContains(t, string(ciphertext), "hunter2",
		"the plaintext must not appear in the row")
}

func TestVersionsAccumulateAndTheLatestWins(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	ctx := context.Background()

	withSecret(t, store, "db-creds", []byte("first"))
	_, err := store.AddVersion(ctx, "db-creds", []byte("second"))
	require.NoError(t, err)

	latest, err := store.Access(ctx, "db-creds", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), latest)
	first, err := store.Access(ctx, "db-creds", "1")
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), first)

	versions, err := store.Versions(ctx, "db-creds")
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, "2", versions[0].ID, "newest first")
	assert.Equal(t, entity.VersionEnabled, versions[0].State)
}

func TestASecretReportsItsLatestVersion(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, "db-creds", entity.Metadata{}))
	empty, err := store.Get(ctx, "db-creds")
	require.NoError(t, err)
	assert.Empty(t, empty.LatestVersion,
		"a secret with no payload reads as not set, not as an error")

	_, err = store.AddVersion(ctx, "db-creds", []byte("hunter2"))
	require.NoError(t, err)
	got, err := store.Get(ctx, "db-creds")
	require.NoError(t, err)
	assert.Equal(t, "1", got.LatestVersion)
}

func TestAStoredVersionSealedUnderARetiredKeyStillOpens(t *testing.T) {
	// The reason key_id is recorded per version. An operator who rotates
	// must not lose everything written before the rotation.
	db := testPool(t)
	ctx := context.Background()

	before := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	withSecret(t, before, "db-creds", []byte("old-value"))

	after := ownStore(t, db, "v2", map[string]string{"v1": keyV1, "v2": keyV2})
	_, err := after.AddVersion(ctx, "db-creds", []byte("new-value"))
	require.NoError(t, err)

	old, err := after.Access(ctx, "db-creds", "1")
	require.NoError(t, err)
	assert.Equal(t, []byte("old-value"), old)
	current, err := after.Access(ctx, "db-creds", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), current)

	var keyIDs []string
	require.NoError(t, db.Select(&keyIDs, "SELECT key_id FROM own_versions ORDER BY version"))
	assert.Equal(t, []string{"v1", "v2"}, keyIDs)
}

func TestKeysInUseSaysWhenARotationIsFinished(t *testing.T) {
	// What an operator has to ask before dropping a key from the config.
	db := testPool(t)
	ctx := context.Background()

	before := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	withSecret(t, before, "db-creds", []byte("old"))

	// Rotating the active key changes nothing on its own: what is already
	// sealed stays sealed under the old one.
	after := ownStore(t, db, "v2", map[string]string{"v1": keyV1, "v2": keyV2})
	inUse, err := after.KeysInUse(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"v1"}, inUse)

	// Only writing re-seals, and now both keys are needed.
	_, err = after.AddVersion(ctx, "db-creds", []byte("new"))
	require.NoError(t, err)
	inUse, err = after.KeysInUse(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"v1", "v2"}, inUse)

	// v1 is safe to drop only once nothing is sealed under it.
	_, err = db.Exec("DELETE FROM own_versions WHERE key_id = 'v1'")
	require.NoError(t, err)
	inUse, err = after.KeysInUse(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"v2"}, inUse)
}

func TestDroppingAKeyStillInUseFailsLoudly(t *testing.T) {
	db := testPool(t)
	ctx := context.Background()

	before := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	withSecret(t, before, "db-creds", []byte("old"))

	// v1 gone from the config while a version still needs it.
	careless := ownStore(t, db, "v2", map[string]string{"v2": keyV2})
	_, err := careless.Access(ctx, "db-creds", "1")
	var backend *entity.BackendCallError
	assert.ErrorAs(t, err, &backend,
		"an unopenable payload must be an error, never empty bytes")
}

func TestTwoStoresOfTheSameTypeDoNotSeeEachOther(t *testing.T) {
	// A deployment may declare a sandbox beside a real one.
	db := testPool(t)
	ctx := context.Background()
	real := mountedOwn(t, db, "local", "v1", map[string]string{"v1": keyV1})
	sandbox := mountedOwn(t, db, "sandbox", "v1", map[string]string{"v1": keyV1})

	withSecret(t, real, "db-creds", []byte("hunter2"))

	realList, err := real.List(ctx)
	require.NoError(t, err)
	assert.Len(t, realList, 1)
	sandboxList, err := sandbox.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, sandboxList)
	_, err = sandbox.Get(ctx, "db-creds")
	assert.ErrorIs(t, err, entity.ErrNotFound)
}

func TestLabelsRoundTripAndCanBeReplaced(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	ctx := context.Background()

	labels := entity.Metadata{"team": "infra"}
	require.NoError(t, store.Create(ctx, "db-creds", labels))
	got, err := store.Get(ctx, "db-creds")
	require.NoError(t, err)
	assert.Equal(t, labels, got.Labels)

	replaced := entity.Metadata{"env": "prod"}
	require.NoError(t, store.SetLabels(ctx, "db-creds", replaced))

	after, err := store.Get(ctx, "db-creds")
	require.NoError(t, err)
	assert.Equal(t, replaced, after.Labels, "replace rather than merge")
}

func TestDeletingASecretTakesItsVersionsWithIt(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	ctx := context.Background()

	withSecret(t, store, "db-creds", []byte("hunter2"))
	require.NoError(t, store.Delete(ctx, "db-creds"))

	var versions int64
	require.NoError(t, db.Get(&versions, "SELECT count(*) FROM own_versions"))
	assert.Zero(t, versions, "an orphaned ciphertext is a secret nobody owns")
}

func TestActingOnASecretThatDoesNotExistIsNotFound(t *testing.T) {
	db := testPool(t)
	store := ownStore(t, db, "v1", map[string]string{"v1": keyV1})
	ctx := context.Background()

	_, err := store.Get(ctx, "missing")
	assert.ErrorIs(t, err, entity.ErrNotFound)
	_, err = store.Access(ctx, "missing", "")
	assert.ErrorIs(t, err, entity.ErrNotFound)
	_, err = store.AddVersion(ctx, "missing", []byte("x"))
	assert.ErrorIs(t, err, entity.ErrNotFound)
	err = store.Delete(ctx, "missing")
	assert.ErrorIs(t, err, entity.ErrNotFound)
}

// The wiring mounts this service behind a Store, so drifting from the seam
// must not compile.
var _ entity.SecretManager = (*secrets.OwnStoreService)(nil)
