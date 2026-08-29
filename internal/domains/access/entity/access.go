// Package entity is how far a caller gets on one secret.
//
// This is the whole authorisation test, and it is deliberately small. Under
// ADR-0002 a delegation carries its own level and nothing caps it, so there
// is no ceiling to intersect and no role to consult: the answer is ownership,
// or the grant addressed to this caller, or nothing.
//
// Keeping it in one function is the point. "Who can see this secret, and how
// far" has to be answerable by reading one list, and that is only true if
// every code path asks the same question the same way.
package entity

import "time"

// Caller is who is asking, as this domain needs to see them.
//
// In Rust this was the identity domain's Actor outright; in Go that import
// would be a cycle, because the Actor answers in this package's Subject and
// Level. The interface carries exactly the questions access asks, and the
// identity Actor satisfies it.
type Caller interface {
	// Handle is the name every service keys and logs on.
	Handle() string
	// IsAdmin is whether this caller holds the operational bypass.
	IsAdmin() bool
	// IsAddressedBy is whether a delegation addressed to `subject` is
	// addressed to THIS caller.
	IsAddressedBy(subject Subject) bool
	// Subjects is every string a delegation could name this caller by.
	Subjects() []Subject
}

// Access is what a caller may do with one secret, and why.
//
// The reason is carried because a refusal owes its reader a sentence, and
// because the audit log records the basis on which a reveal was allowed.
type Access struct {
	// Level is nil when nothing opens the secret at all.
	Level *Level
	Basis Basis
	// Keys is which keys of a key/value secret are open, or nil for all of
	// them.
	Keys []string
}

// Basis is why a caller may do what they may.
//
// A comparable value rather than a set of types, so a test and an audit line
// can ask "is this exactly Owner" with ==.
type Basis struct {
	kind string
	// subject is who a delegated grant was addressed to — a handle or a group
	// name, which is what a person needs in order to know where their access
	// came from.
	subject string
}

// BasisNothing: nothing opens this secret for this caller.
var BasisNothing = Basis{kind: "nothing"}

// BasisOwner: they own it, so they run it outright whatever role they hold.
var BasisOwner = Basis{kind: "owner"}

// BasisAdmin: the operational bypass.
var BasisAdmin = Basis{kind: "admin"}

// BasisDelegated: a grant, and who it was addressed to.
func BasisDelegated(subject string) Basis {
	return Basis{kind: "delegated", subject: subject}
}

// DelegatedTo is who the grant behind this basis was addressed to, when it
// was a grant at all.
func (b Basis) DelegatedTo() (string, bool) {
	return b.subject, b.kind == "delegated"
}

func (b Basis) String() string {
	if b.kind == "delegated" {
		return "delegated:" + b.subject
	}
	return b.kind
}

// NoAccess is nothing at all.
func NoAccess() Access {
	return Access{Level: nil, Basis: BasisNothing, Keys: nil}
}

// Allows is whether this opens the secret at least as far as `wanted`.
func (a Access) Allows(wanted Level) bool {
	return a.Level != nil && *a.Level >= wanted
}

// AllowsKey is whether this opens `key` of a key/value secret at `wanted`.
func (a Access) AllowsKey(wanted Level, key string) bool {
	if !a.Allows(wanted) {
		return false
	}
	if a.Keys == nil {
		return true
	}
	for _, k := range a.Keys {
		if k == key {
			return true
		}
	}
	return false
}

// IsVisible is whether the secret's existence should be disclosed at all.
func (a Access) IsVisible() bool {
	return a.Level != nil
}

// Resolve is how far `actor` gets on the secret that `ownership` and `grants`
// describe.
//
// `grants` is every delegation written against that secret, whoever it is
// addressed to — this function picks out the ones that name the caller. That
// is deliberate: a caller-filtered query would put half the authorisation
// rule in SQL, where the next person to write a query is free to get it
// wrong.
func Resolve(actor Caller, ownership *Ownership, grants []Delegation, now time.Time) Access {
	// An owner runs their secret outright: change it, delegate it, revoke a
	// grant, transfer it. Checked before admin so the audit basis names the
	// narrower, truer reason.
	if ownership != nil && ownership.Owner == actor.Handle() {
		return Access{Level: levelOf(Write), Basis: BasisOwner, Keys: nil}
	}

	if actor.IsAdmin() {
		return Access{Level: levelOf(Write), Basis: BasisAdmin, Keys: nil}
	}

	// The best active grant addressed to this caller. Best rather than first:
	// a person may be named directly and through a group, and the answer is
	// the most that was granted, not whichever row the database returned
	// first.
	var best *Delegation
	for i := range grants {
		grant := &grants[i]
		if !grant.IsActive(now) || !actor.IsAddressedBy(grant.Subject) {
			continue
		}
		if best == nil || grant.Level > best.Level {
			best = grant
		}
	}

	if best == nil {
		return NoAccess()
	}
	return Access{
		Level: levelOf(best.Level),
		Basis: BasisDelegated(best.Subject.ID()),
		Keys:  best.ScopedKeys(),
	}
}

func levelOf(l Level) *Level {
	return &l
}
