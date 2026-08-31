// Package secrets is the inventory, and the seam over whatever holds it.
//
// One deliberate deviation from the Rust layout: Store and Registry live here
// rather than in the entity package. config already imports entity for the
// Metadata and identifier types, and a Store carries its config.StoreConfig —
// in Rust both directions were fine across modules of one crate, in Go they
// would be an import cycle.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/kotsmile/keyway/config"
	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// Store is one configured backing service: a SecretManager with the scope,
// the verbs and the protections its declaration gave it.
//
// Every call goes through here rather than to the adapter directly. `allow`
// is a fence rather than a hint, and putting it in one place means a new
// adapter cannot forget to check it — the worst kind of bug to ship in a
// secrets tool, because nothing about it looks wrong until somebody deletes
// a production secret from a Store that was meant to be read-only.
type Store struct {
	config  config.StoreConfig
	manager entity.SecretManager
	// observe records each backend call. Injected, and nil for a Store nobody
	// asked to instrument.
	observe BackendObserver
}

// NotAllowedError is a verb this deployment did not grant here.
type NotAllowedError struct {
	Store entity.StoreID
	Verb  config.Verb
}

func (e *NotAllowedError) Error() string {
	return fmt.Sprintf("%s does not allow %q", e.Store.String(), string(e.Verb))
}

// ProtectedError is a secret a reconciler owns. Reported with the marker that
// says so, because "you may not edit this" without naming the owner leaves
// the reader with nowhere to go.
type ProtectedError struct {
	Name   string
	Marker string
}

func (e *ProtectedError) Error() string {
	return fmt.Sprintf("%s is managed by %s; edit the source instead", e.Name, e.Marker)
}

// BackendObserver records one timed backend call: Store id, operation, "ok"
// or "error", and the elapsed seconds. The labels stay a bounded set — Store
// and operation, never a secret's name.
//
// It is the seam the telemetry port fills. A dependency of a Store, passed to
// the constructor, rather than the package-level variable this used to be: a
// mutable global assigned from main is a dependency nothing declares, that
// two tests cannot hold different opinions about, and that reads as
// configured-somewhere-else at every call site. Everything else keyway wires
// is wired in main.go by name, and so is this.
type BackendObserver func(store, operation, outcome string, seconds float64)

// operation is the name a backend call is metered under.
//
// A bounded set, spelled once: an operation label is a time series per
// distinct value, and one built from a caller's string would be a metrics
// cardinality problem that only appears in production.
type operation string

const (
	opList       operation = "list"
	opGet        operation = "get"
	opVersions   operation = "versions"
	opAccess     operation = "access"
	opAddVersion operation = "add_version"
	opSetLabels  operation = "set_labels"
	opCreate     operation = "create"
	opDelete     operation = "delete"
)

// NewStore mounts a configured Store over its adapter.
//
// observe may be nil, which is what a test that does not care about metrics
// passes: the timing is then not recorded, and nothing else changes.
func NewStore(cfg config.StoreConfig, manager entity.SecretManager, observe BackendObserver) *Store {
	return &Store{config: cfg, manager: manager, observe: observe}
}

// ID is the Store's stable handle.
func (s *Store) ID() entity.StoreID { return s.config.ID }

// Config is the declaration this Store was mounted from.
func (s *Store) Config() config.StoreConfig { return s.config }

// List is every secret this Store exposes: what the backend holds, narrowed
// by `select`.
//
// It fails when `read` is not allowed, or the backend fails.
func (s *Store) List(ctx context.Context) ([]entity.Secret, error) {
	if err := s.require(config.Read); err != nil {
		return nil, err
	}
	listed, err := timed(s, opList, func() ([]entity.Secret, error) { return s.manager.List(ctx) })
	if err != nil {
		return nil, err
	}
	secrets := listed[:0]
	for _, secret := range listed {
		if !s.selects(secret) {
			continue
		}
		secret.Store = s.config.ID
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// Get is one secret's metadata.
//
// A secret outside `select` reports entity.ErrNotFound rather than a
// refusal: a Store that does not expose something should not confirm it
// exists.
//
// It fails when `read` is not allowed, the secret is not exposed, or the
// backend fails.
func (s *Store) Get(ctx context.Context, name entity.SecretName) (entity.Secret, error) {
	if err := s.require(config.Read); err != nil {
		return entity.Secret{}, err
	}
	secret, err := timed(s, opGet, func() (entity.Secret, error) { return s.manager.Get(ctx, name) })
	if err != nil {
		return entity.Secret{}, err
	}
	if !s.selects(secret) {
		return entity.Secret{}, entity.ErrNotFound
	}
	secret.Store = s.config.ID
	return secret, nil
}

// Versions is the revision series, newest first.
//
// It fails as Get does.
func (s *Store) Versions(ctx context.Context, name entity.SecretName) ([]entity.Version, error) {
	if _, err := s.Get(ctx, name); err != nil {
		return nil, err
	}
	return timed(s, opVersions, func() ([]entity.Version, error) { return s.manager.Versions(ctx, name) })
}

// Access is one version's payload. An empty version means the latest.
//
// It fails as Get does.
func (s *Store) Access(ctx context.Context, name entity.SecretName, version entity.VersionID) ([]byte, error) {
	if _, err := s.Get(ctx, name); err != nil {
		return nil, err
	}
	return timed(s, opAccess, func() ([]byte, error) { return s.manager.Access(ctx, name, version) })
}

// AddVersion writes a new revision.
//
// It fails when `edit` is not allowed, a reconciler owns the secret, or the
// backend fails.
func (s *Store) AddVersion(ctx context.Context, name entity.SecretName, payload []byte) (entity.Version, error) {
	if err := s.require(config.Edit); err != nil {
		return entity.Version{}, err
	}
	secret, err := s.Get(ctx, name)
	if err != nil {
		return entity.Version{}, err
	}
	if err := s.requireUnprotected(secret); err != nil {
		return entity.Version{}, err
	}
	return timed(s, opAddVersion, func() (entity.Version, error) { return s.manager.AddVersion(ctx, name, payload) })
}

// SetLabels replaces a secret's labels.
//
// It fails as AddVersion does.
func (s *Store) SetLabels(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	if err := s.require(config.Edit); err != nil {
		return err
	}
	secret, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	if err := s.requireUnprotected(secret); err != nil {
		return err
	}
	_, err = timed(s, opSetLabels, func() (struct{}, error) { return struct{}{}, s.manager.SetLabels(ctx, name, labels) })
	return err
}

// Create brings a new secret into existence.
//
// It fails when `create` is not allowed, or the backend fails.
func (s *Store) Create(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	if err := s.require(config.Create); err != nil {
		return err
	}
	_, err := timed(s, opCreate, func() (struct{}, error) { return struct{}{}, s.manager.Create(ctx, name, labels) })
	return err
}

// Delete destroys a secret and every version of it.
//
// It fails when `delete` is not allowed, a reconciler owns the secret, or the
// backend fails.
func (s *Store) Delete(ctx context.Context, name entity.SecretName) error {
	if err := s.require(config.Delete); err != nil {
		return err
	}
	secret, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	if err := s.requireUnprotected(secret); err != nil {
		return err
	}
	_, err = timed(s, opDelete, func() (struct{}, error) { return struct{}{}, s.manager.Delete(ctx, name) })
	return err
}

// timed times one backend call and records how it went.
//
// Here rather than in each adapter, for the same reason `allow` is: a new
// backend cannot forget, and the labels stay a bounded set.
func timed[T any](s *Store, op operation, call func() (T, error)) (T, error) {
	if s.observe == nil {
		return call()
	}
	started := time.Now()
	result, err := call()
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	s.observe(s.config.ID.String(), string(op), outcome, time.Since(started).Seconds())
	return result, err
}

func (s *Store) require(verb config.Verb) error {
	if s.config.Can(verb) {
		return nil
	}
	return &NotAllowedError{Store: s.config.ID, Verb: verb}
}

func (s *Store) selects(secret entity.Secret) bool {
	return s.config.Select.MatchesAll(secret.Labels, secret.Annotations)
}

func (s *Store) requireUnprotected(secret entity.Secret) error {
	protect := s.config.Protect
	if !protect.MatchesAny(secret.Labels, secret.Annotations) {
		return nil
	}
	marker, ok := protect.FirstMatch(secret.Labels, secret.Annotations)
	if !ok {
		marker = "a reconciler"
	}
	return &ProtectedError{Name: secret.Reference(), Marker: marker}
}
