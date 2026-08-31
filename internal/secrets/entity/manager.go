package entity

import (
	"context"
	"errors"
	"fmt"
)

// SecretManager is one backend's port — the seam that makes keyway an
// aggregator rather than a front-end for a single secret manager.
//
// The interface is deliberately small and deliberately CRUD-shaped, because
// that is the intersection of what secret managers actually agree on: a named
// secret, an ordered series of immutable versions, and a blob per version.
// Everything richer — replication policies, leases, rotation schedules — is
// the backend's business and stays inside its implementation. An interface
// carrying the union of every backend's features is a union nobody can
// implement.
//
// Note what it does NOT know about: key/value. A kv secret is a JSON blob by
// the time it reaches here, so a backend with native kv can serve it natively
// and one without is not asked to fake it.
//
// Implementations must be safe for concurrent use: keyway serves several
// requests at once and holds one instance per Store for the process's life.
//
// Implementations do not enforce `allow`, `select` or `protect` — the Store
// does that around them, so no adapter can forget to.
type SecretManager interface {
	// List is every secret's metadata, no payloads. This is the first screen
	// of the app, so an implementation should page through the backend rather
	// than fan out a request per secret.
	//
	// An adapter leaves Secret.Store unset: it has no reason to know its own
	// Store id, and the Store stamps every listing with it.
	List(ctx context.Context) ([]Secret, error)

	// Get is one secret's metadata.
	Get(ctx context.Context, name SecretName) (Secret, error)

	// Versions is the revision series, newest first.
	Versions(ctx context.Context, name SecretName) ([]Version, error)

	// Access is one version's payload. An empty version means the latest.
	//
	// The name and the version are separate types on purpose: this is the
	// signature where passing them the wrong way round would read a value
	// under an id nobody asked for.
	Access(ctx context.Context, name SecretName, version VersionID) ([]byte, error)

	// SetLabels replaces a secret's labels with the map given — replace
	// rather than merge, because that is what the backends offer. The caller
	// merges.
	SetLabels(ctx context.Context, name SecretName, labels Metadata) error

	// Create makes an empty secret. Split from AddVersion because that is the
	// backends' own shape, and because it lets a create fail on "already
	// exists" without having first written a payload somewhere.
	Create(ctx context.Context, name SecretName, labels Metadata) error

	// AddVersion writes a new revision and returns it.
	AddVersion(ctx context.Context, name SecretName, payload []byte) (Version, error)

	// Delete removes the secret and every version of it.
	Delete(ctx context.Context, name SecretName) error
}

// ErrNotFound is no such secret. Kept distinct from every other failure
// because an unknown Store id in a URL must be indistinguishable from an
// unknown secret, and only the caller of the registry can arrange that.
var ErrNotFound = errors.New("no such secret")

// NoSuchVersionError is a secret that exists but a version that does not.
type NoSuchVersionError struct {
	Version VersionID
}

func (e *NoSuchVersionError) Error() string {
	return fmt.Sprintf("no such version %q", e.Version.String())
}

// InvalidNameError is a name the backend will not accept.
type InvalidNameError struct {
	Name   SecretName
	Reason string
}

func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("invalid name %q: %s", e.Name, e.Reason)
}

// BackendCallError is anything the backend itself reported: a transport
// failure, a refused credential, a quota — wrapped with a sentence saying
// what was being done.
type BackendCallError struct {
	Context string
	Err     error
}

func (e *BackendCallError) Error() string {
	return fmt.Sprintf("%s: %v", e.Context, e.Err)
}

func (e *BackendCallError) Unwrap() error { return e.Err }

// Backend wraps a backend's own error with a sentence saying what was being
// done.
func Backend(context string, err error) error {
	return &BackendCallError{Context: context, Err: err}
}
