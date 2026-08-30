package entity

import (
	"time"

	"github.com/google/uuid"
)

// Delegation is a grant over one secret, to one subject, at one level.
//
// It is self-describing: what it says is what it opens, and no role caps it
// (ADR-0002). The grantee still cannot re-delegate it or transfer it — those
// belong to ownership, which is a different act with a different audit line.
type Delegation struct {
	ID      uuid.UUID
	Store   string
	Secret  string
	Subject Subject
	Level   Level
	// Keys narrows the grant to some entries of a key/value secret; empty is
	// the whole secret. This is what makes it safe to bundle a bot's
	// credentials into one secret and still hand out exactly one of them.
	Keys      []string
	GrantedBy string
	GrantedAt time.Time
	// ExpiresAt nil is indefinite, which is the common case.
	ExpiresAt *time.Time
	// Note is why it was granted: the sentence the next admin needs in order
	// to decide whether it is still true.
	Note string
}

// IsActive is whether this grant opens anything at `now`.
//
// An expired row is kept rather than deleted: "who used to be able to see
// this" is a question an incident asks, and a deleted row cannot answer it.
func (d Delegation) IsActive(now time.Time) bool {
	return d.ExpiresAt == nil || d.ExpiresAt.After(now)
}

// CoversKey is whether this grant covers `key` of a key/value secret.
//
// An empty key list is the whole secret, so it covers everything — including
// keys that did not exist when the grant was written. That is the intended
// reading: the grant names a secret, not a snapshot of it.
func (d Delegation) CoversKey(key string) bool {
	if len(d.Keys) == 0 {
		return true
	}
	for _, k := range d.Keys {
		if k == key {
			return true
		}
	}
	return false
}

// ScopedKeys is the keys this grant opens, or nil for the whole secret.
func (d Delegation) ScopedKeys() []string {
	if len(d.Keys) == 0 {
		return nil
	}
	return d.Keys
}

// Ownership is who a secret belongs to.
//
// Always a person: a group cannot own a secret, because an owner is who you
// ASK about one.
type Ownership struct {
	Store  string
	Secret string
	Owner  string
	// Since is when they became the owner — set on create, reset by a
	// transfer. So it reads as "has held this since", not "the secret was
	// created then".
	Since time.Time
}
