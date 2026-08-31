// What a Store enforces around whatever adapter it wraps.
//
// These are the tests that matter most in this package: every one of them is
// a way a future adapter could quietly do the wrong thing if the fence were
// in the adapter rather than here.

package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/kotsmile/keyway/config"
	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// spy is an adapter that records what it was actually asked to do.
//
// It enforces nothing at all — deliberately, since the point of these tests
// is that the Store refuses before the adapter is ever reached.
type spy struct {
	secrets []entity.Secret

	mu    sync.Mutex
	calls []string
}

func (s *spy) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *spy) wasAskedTo(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

func (s *spy) List(context.Context) ([]entity.Secret, error) {
	s.record("list")
	out := make([]entity.Secret, len(s.secrets))
	copy(out, s.secrets)
	return out, nil
}

func (s *spy) Get(_ context.Context, name entity.SecretName) (entity.Secret, error) {
	s.record("get")
	for _, secret := range s.secrets {
		if secret.Name == name {
			return secret, nil
		}
	}
	return entity.Secret{}, entity.ErrNotFound
}

func (s *spy) Versions(context.Context, entity.SecretName) ([]entity.Version, error) {
	s.record("versions")
	return []entity.Version{{ID: "1", State: entity.VersionEnabled}}, nil
}

func (s *spy) Access(context.Context, entity.SecretName, entity.VersionID) ([]byte, error) {
	s.record("access")
	return []byte("payload"), nil
}

func (s *spy) SetLabels(context.Context, entity.SecretName, entity.Metadata) error {
	s.record("set_labels")
	return nil
}

func (s *spy) Create(context.Context, entity.SecretName, entity.Metadata) error {
	s.record("create")
	return nil
}

func (s *spy) AddVersion(context.Context, entity.SecretName, []byte) (entity.Version, error) {
	s.record("add_version")
	return entity.Version{ID: "2", State: entity.VersionEnabled}, nil
}

func (s *spy) Delete(context.Context, entity.SecretName) error {
	s.record("delete")
	return nil
}

func secret(name entity.SecretName, labels map[string]string) entity.Secret {
	return entity.Secret{
		Name:          name,
		Labels:        labels,
		LatestVersion: "1",
	}
}

func storeConfig(t *testing.T, text string) config.StoreConfig {
	t.Helper()
	var cfg config.StoreConfig
	require.NoError(t, yaml.Unmarshal([]byte(text), &cfg), "valid store config")
	return cfg
}

// mountedWithSpy mounts a Store, keeping a handle on the spy so a test can
// ask what the adapter was actually asked to do.
func mountedWithSpy(t *testing.T, text string, secrets []entity.Secret) (*Store, *spy) {
	t.Helper()
	adapter := &spy{secrets: secrets}
	// No observer: these tests are about the fence, not the metrics.
	return NewStore(storeConfig(t, text), adapter, nil), adapter
}

func mounted(t *testing.T, text string, secrets []entity.Secret) *Store {
	t.Helper()
	store, _ := mountedWithSpy(t, text, secrets)
	return store
}

// The `type` is irrelevant to what these tests assert — the adapter is the
// spy below — but the config schema refuses a kind no SecretManager answers
// to, so the fixtures name a real one.
const (
	readOnly = "id: prod\ntype: keyway\nallow: [read]\n"
	readEdit = "id: prod\ntype: keyway\nallow: [read, edit]\n"
)

func TestAVerbTheDeploymentWithheldNeverReachesTheAdapter(t *testing.T) {
	store, adapter := mountedWithSpy(t, readOnly, []entity.Secret{secret("db", nil)})

	err := store.Delete(context.Background(), "db")
	var notAllowed *NotAllowedError
	require.ErrorAs(t, err, &notAllowed)

	// The whole point of the fence living here: an adapter that forgot to
	// check `allow` could not have destroyed anything, because it was never
	// asked to.
	assert.False(t, adapter.wasAskedTo("delete"),
		"the refusal must happen before the adapter, not inside it")
}

func TestEditingIsNotCreatingAndNotDestroying(t *testing.T) {
	store := mounted(t, readEdit, []entity.Secret{secret("db", nil)})
	ctx := context.Background()

	_, err := store.AddVersion(ctx, "db", []byte("new"))
	assert.NoError(t, err)

	var notAllowed *NotAllowedError
	err = store.Create(ctx, "other", entity.Metadata{})
	assert.ErrorAs(t, err, &notAllowed)
	err = store.Delete(ctx, "db")
	assert.ErrorAs(t, err, &notAllowed)
}

func TestSelectNarrowsTheListing(t *testing.T) {
	text := "id: prod\ntype: keyway\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n"
	store := mounted(t, text, []entity.Secret{
		secret("mine", map[string]string{"keyway": "true"}),
		secret("someone-elses", nil),
	})

	listed, err := store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, entity.SecretName("mine"), listed[0].Name)
}

func TestASecretOutsideSelectIsNotFoundRatherThanRefused(t *testing.T) {
	// A Store that does not expose something must not confirm it exists.
	text := "id: prod\ntype: keyway\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n"
	store := mounted(t, text, []entity.Secret{secret("someone-elses", nil)})

	_, err := store.Get(context.Background(), "someone-elses")
	assert.ErrorIs(t, err, entity.ErrNotFound)
}

func TestAReconcilerOwnedSecretIsReadableButNotEditable(t *testing.T) {
	store := mounted(t, readEdit, []entity.Secret{
		secret("db", map[string]string{"reconcile.external-secrets.io/managed": "true"}),
	})
	ctx := context.Background()

	// Visible: hiding it would be worse than refusing the edit.
	_, err := store.Get(ctx, "db")
	assert.NoError(t, err)
	_, err = store.Access(ctx, "db", "")
	assert.NoError(t, err)

	_, err = store.AddVersion(ctx, "db", []byte("new"))
	var protected *ProtectedError
	require.ErrorAs(t, err, &protected, "expected a protected refusal, got %v", err)
	// The refusal names the marker, so its reader knows which tool owns it.
	assert.Contains(t, protected.Marker, "external-secrets", "marker was %q", protected.Marker)
}

func TestProtectionCoversLabelsADeploymentAddedItself(t *testing.T) {
	text := "id: prod\ntype: keyway\nallow: [read, edit]\nprotect:\n  labels:\n    owned-by: terraform\n"
	store := mounted(t, text, []entity.Secret{
		secret("db", map[string]string{"owned-by": "terraform"}),
	})

	_, err := store.AddVersion(context.Background(), "db", []byte("x"))
	var protected *ProtectedError
	assert.ErrorAs(t, err, &protected)
}

func TestAListingIsStampedWithTheStoreItCameFrom(t *testing.T) {
	// An adapter has no reason to know its own Store id; the Store fills it
	// in so a cross-store listing can be keyed without every adapter
	// cooperating.
	store := mounted(t, readOnly, []entity.Secret{secret("db", nil)})
	ctx := context.Background()

	listed, err := store.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, entity.StoreID("prod"), listed[0].Store)

	got, err := store.Get(ctx, "db")
	require.NoError(t, err)
	assert.Equal(t, entity.StoreID("prod"), got.Store)
}

func TestARegistryKeepsDeclarationOrder(t *testing.T) {
	var stores []*Store
	for _, id := range []string{"b", "a", "c"} {
		stores = append(stores, mounted(t, fmt.Sprintf("id: %s\ntype: keyway\nallow: [read]\n", id), nil))
	}
	registry, err := NewRegistry(stores)
	require.NoError(t, err)

	var ids []entity.StoreID
	for _, store := range registry.All() {
		ids = append(ids, store.ID())
	}
	assert.Equal(t, []entity.StoreID{"b", "a", "c"}, ids, "the config decides what comes first")
}

func TestARegistryRefusesTwoStoresOnOneID(t *testing.T) {
	var stores []*Store
	for range 2 {
		stores = append(stores, mounted(t, readOnly, nil))
	}
	_, err := NewRegistry(stores)
	var duplicate *DuplicateStoreError
	assert.ErrorAs(t, err, &duplicate)
}

func TestAnUnknownStoreIDResolvesToNothing(t *testing.T) {
	registry, err := NewRegistry([]*Store{mounted(t, readOnly, nil)})
	require.NoError(t, err)
	assert.NotNil(t, registry.Get("prod"))
	assert.Nil(t, registry.Get("does-not-exist"))
}

// ---- the backend observer --------------------------------------------------

func TestEveryBackendCallIsReportedWithABoundedLabelSet(t *testing.T) {
	// The observer is a dependency of the Store now, not a package-level
	// variable main assigns: two tests can hold different opinions about it,
	// and every call site says where it came from.
	type call struct {
		store     string
		operation string
		outcome   string
	}
	var mu sync.Mutex
	var seen []call
	observe := func(store, operation, outcome string, seconds float64) {
		mu.Lock()
		defer mu.Unlock()
		assert.GreaterOrEqual(t, seconds, 0.0)
		seen = append(seen, call{store, operation, outcome})
	}

	mounted := NewStore(storeConfig(t, readEdit),
		&spy{secrets: []entity.Secret{secret("db", nil)}}, observe)
	ctx := context.Background()
	_, err := mounted.List(ctx)
	require.NoError(t, err)
	_, err = mounted.AddVersion(ctx, "db", []byte("new"))
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	// The labels are the Store id and a fixed operation word — never a
	// secret's name, which would both explode cardinality and publish the
	// inventory to whoever can reach /metrics.
	assert.Contains(t, seen, call{"prod", "list", "ok"})
	assert.Contains(t, seen, call{"prod", "add_version", "ok"})
	for _, c := range seen {
		assert.Equal(t, "prod", c.store)
		assert.NotEqual(t, "db", c.operation)
		assert.NotEqual(t, "db", c.outcome)
	}
}

func TestARefusalIsNotABackendCall(t *testing.T) {
	// `allow` is checked before the adapter is reached, so a refused verb
	// must not show up as backend latency.
	var calls int
	observe := func(string, string, string, float64) { calls++ }
	mounted := NewStore(storeConfig(t, readOnly), &spy{}, observe)

	err := mounted.Create(context.Background(), "db", entity.Metadata{})
	var notAllowed *NotAllowedError
	require.ErrorAs(t, err, &notAllowed)
	assert.Zero(t, calls, "nothing reached the backend, so nothing was timed")
}

func TestAStoreWithNoObserverStillServes(t *testing.T) {
	// Metrics are an option, not a requirement: a Store mounted without one
	// behaves identically. This is also every other test in this file.
	mounted := NewStore(storeConfig(t, readOnly),
		&spy{secrets: []entity.Secret{secret("db", nil)}}, nil)
	listed, err := mounted.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, listed, 1)
}
