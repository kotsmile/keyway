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

func (s *spy) Get(_ context.Context, name string) (entity.Secret, error) {
	s.record("get")
	for _, secret := range s.secrets {
		if secret.Name == name {
			return secret, nil
		}
	}
	return entity.Secret{}, entity.ErrNotFound
}

func (s *spy) Versions(context.Context, string) ([]entity.Version, error) {
	s.record("versions")
	return []entity.Version{{ID: "1", State: entity.VersionEnabled}}, nil
}

func (s *spy) Access(context.Context, string, string) ([]byte, error) {
	s.record("access")
	return []byte("payload"), nil
}

func (s *spy) SetLabels(context.Context, string, entity.Metadata) error {
	s.record("set_labels")
	return nil
}

func (s *spy) Create(context.Context, string, entity.Metadata) error {
	s.record("create")
	return nil
}

func (s *spy) AddVersion(context.Context, string, []byte) (entity.Version, error) {
	s.record("add_version")
	return entity.Version{ID: "2", State: entity.VersionEnabled}, nil
}

func (s *spy) Delete(context.Context, string) error {
	s.record("delete")
	return nil
}

func secret(name string, labels map[string]string) entity.Secret {
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
	return NewStore(storeConfig(t, text), adapter), adapter
}

func mounted(t *testing.T, text string, secrets []entity.Secret) *Store {
	t.Helper()
	store, _ := mountedWithSpy(t, text, secrets)
	return store
}

const (
	readOnly = "id: prod\ntype: spy\nallow: [read]\n"
	readEdit = "id: prod\ntype: spy\nallow: [read, edit]\n"
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
	text := "id: prod\ntype: spy\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n"
	store := mounted(t, text, []entity.Secret{
		secret("mine", map[string]string{"keyway": "true"}),
		secret("someone-elses", nil),
	})

	listed, err := store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "mine", listed[0].Name)
}

func TestASecretOutsideSelectIsNotFoundRatherThanRefused(t *testing.T) {
	// A Store that does not expose something must not confirm it exists.
	text := "id: prod\ntype: spy\nallow: [read]\nselect:\n  labels:\n    keyway: \"true\"\n"
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
	text := "id: prod\ntype: spy\nallow: [read, edit]\nprotect:\n  labels:\n    owned-by: terraform\n"
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
	assert.Equal(t, "prod", listed[0].Store)

	got, err := store.Get(ctx, "db")
	require.NoError(t, err)
	assert.Equal(t, "prod", got.Store)
}

func TestARegistryKeepsDeclarationOrder(t *testing.T) {
	var stores []*Store
	for _, id := range []string{"b", "a", "c"} {
		stores = append(stores, mounted(t, fmt.Sprintf("id: %s\ntype: spy\nallow: [read]\n", id), nil))
	}
	registry, err := NewRegistry(stores)
	require.NoError(t, err)

	var ids []string
	for _, store := range registry.All() {
		ids = append(ids, store.ID())
	}
	assert.Equal(t, []string{"b", "a", "c"}, ids, "the config decides what comes first")
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
