// What a Store, a secret and a version are CALLED.
//
// Three named types rather than three strings, because they are the three
// things this domain passes around together and in that order:
// `Access(ctx, name, version)`, `AAD(store, name, version)`,
// `GrantsOn(ctx, store, secret)`. Every one of those is a pair or a triple of
// bare strings that the compiler was perfectly happy to see swapped — and a
// swapped store and name in a secrets console is a reveal of the wrong
// secret's value, which is the one bug class this system exists to prevent.
//
// They are named string types rather than structs with a hidden field, which
// is the compromise the rest of the codebase already makes (config.Verb,
// audit.Action): a conversion is still possible where a caller insists, but
// nothing does it by ACCIDENT, and every place that reads one from outside —
// the config file, a URL, a request body, a database row — goes through a
// constructor here. In exchange they marshal, bind and scan exactly as the
// strings they replaced, so neither the wire nor the schema moves.
//
// The identifiers live in the secrets domain because a Store and a secret are
// its concepts; access, audit and the transport key their rows and their URLs
// by them, and import them from here rather than re-declaring what they mean.

package entity

import "errors"

// StoreID is one configured backing service's stable handle.
//
// It is what a URL names, what the delegations, ownership and audit rows are
// keyed by, and what a Store's own listing is stamped with. Renaming one
// orphans every grant written against it, so it is chosen once and left
// alone.
type StoreID string

// SecretName is what a backend knows a secret by.
//
// Not what keyway ADDRESSES it by — that is a uuid — because the name is
// somebody else's contract: External Secrets manifests and whatever tooling
// already exists address these by name.
type SecretName string

// VersionID is one revision, as its backend identifies it.
//
// Deliberately opaque: a number in keyway's own Store, an ordered id in
// Google's, an unordered uuid in AWS's, a resourceVersion in Kubernetes'.
// Nothing outside a SecretManager may parse one, so nothing here validates a
// shape — the type exists to stop a version being passed where a name is
// wanted.
type VersionID string

// ErrStoreIDRequired is an unnamed Store.
//
// The only rule this type carries. A Store id is otherwise whatever a
// deployment chose years ago and keyed its grants by, so anything narrower
// would orphan somebody's rows on upgrade.
var ErrStoreIDRequired = errors.New("a store needs an `id`")

// NewStoreID reads a Store id from configuration.
//
// It fails on the empty id, which is not a Store anybody could address: the
// registry would key it under "", every URL naming it would be
// indistinguishable from a URL naming none, and its grants could never be
// told from another empty one's.
func NewStoreID(raw string) (StoreID, error) {
	if raw == "" {
		return "", ErrStoreIDRequired
	}
	return StoreID(raw), nil
}

// String is the id as a URL, a column and a metric label spell it.
func (s StoreID) String() string { return string(s) }

// NewSecretName reads a name a caller or a backend supplied.
//
// It fails on the empty name, with the same InvalidNameError keyway's own
// Store already answered with — the wording is what a caller reads, so it
// stays where it was even though the check has moved up.
//
// Nothing else is refused here. Every backend has its own grammar (Google's
// is not Kubernetes', which is not Lockbox's), and a name this build refuses
// is a secret this build cannot show — so a name keyway does not like is the
// backend's to reject, at the call, where the reason can be specific.
func NewSecretName(raw string) (SecretName, error) {
	if raw == "" {
		return "", &InvalidNameError{Name: "", Reason: "a name is required"}
	}
	return SecretName(raw), nil
}

// String is the name as the backend spells it.
func (n SecretName) String() string { return string(n) }

// String is the version as the backend spells it.
func (v VersionID) String() string { return string(v) }

// IsLatest is whether this names no particular version.
//
// The empty version means "whatever an unqualified read resolves to", which
// every adapter maps to its own backend's notion of current — a stage in AWS,
// the highest number in keyway's own Store.
func (v VersionID) IsLatest() bool { return v == "" }
