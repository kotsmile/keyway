// How a secret is addressed.
//
// Every route, every API call and every link is a uuid; the name is a label
// people read. That is not keyway's preference so much as a consequence: the
// name is somebody else's contract — External Secrets manifests and whatever
// tooling already exists address these by name — so renaming secrets to uuids
// would break every one of those to buy keyway an id it can carry in a label
// instead.

package entity

import "github.com/google/uuid"

// IDLabel is the backend label keyway keeps a secret's uuid in.
//
// A label rather than the name, and one that satisfies the strictest grammar
// among the backends (lowercase letters, digits, `-`, `_`, at most 63
// characters). A uuid in canonical form is 36 lowercase hex characters and
// dashes, so nothing has to be encoded.
const IDLabel = "keyway-id"

// idNamespace seeds the derived ids below. A fixed random uuid, never
// changed: changing it renames every unlabelled secret in one release. The
// same sixteen bytes the Rust implementation spelled as a u128.
var idNamespace = uuid.MustParse("9f2c4e8a-7b31-4d6f-a05e-1c837d942b60")

// IDOf is the uuid a secret is addressed by.
//
// The label is the answer whenever the backend carries one. When it does not
// — every secret that predates keyway, and everything another tool created —
// the id is DERIVED from (store, name) rather than minted at random, and that
// is the whole reason this can ship without a backfill: an inventory of a
// hundred untouched secrets is addressable from the first request.
//
// Derivation is v5, so it is stable across processes, restarts and replicas —
// three keyway pods answer the same uuid for the same secret without
// coordinating.
func IDOf(store StoreID, name SecretName, labels Metadata) uuid.UUID {
	if labelled, err := uuid.Parse(labels[IDLabel]); err == nil {
		return labelled
	}
	return Derive(store, name)
}

// Derive is the id a secret takes when the backend carries no label.
func Derive(store StoreID, name SecretName) uuid.UUID {
	return uuid.NewSHA1(idNamespace, []byte(store.String()+"/"+name.String()))
}

// IDFor is the id this secret answers to.
func IDFor(secret Secret) uuid.UUID {
	return IDOf(secret.Store, secret.Name, secret.Labels)
}

// IsLabelled is whether this secret already carries its id, or is still being
// addressed by a derived one.
//
// keyway writes the label the first time somebody opens a secret, purely so
// the id stops depending on the name.
func IsLabelled(secret Secret) bool {
	_, err := uuid.Parse(secret.Labels[IDLabel])
	return err == nil
}

// AdoptionLabels is the labels a secret should carry once adopted, or nil if
// it already does.
func AdoptionLabels(secret Secret) Metadata {
	if IsLabelled(secret) {
		return nil
	}
	labels := make(Metadata, len(secret.Labels)+1)
	for k, v := range secret.Labels {
		labels[k] = v
	}
	labels[IDLabel] = IDFor(secret).String()
	return labels
}
