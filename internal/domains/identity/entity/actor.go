// Package entity is who is asking.
//
// Only the Actor and its Role are ported so far — they are what the access
// and audit domains speak in. The rest of the identity domain (sessions,
// OIDC, the remembered users table) is a later ticket.
package entity

import (
	"sort"

	access "github.com/kotsmile/keyway/internal/domains/access/entity"
)

// Actor is who is asking.
//
// Resolved once at the edge and never re-derived: a browser session reads all
// of this from the claim, and an API token names a handle and takes the
// groups keyway remembered (ADR-0004).
type Actor struct {
	handle string
	groups map[string]struct{}
	roles  map[Role]struct{}
	// viaToken is the public id of the API token this request arrived on, if
	// it did. Kept so an audit row can name WHICH credential acted, not merely
	// which account.
	viaToken string
}

// Role is what a person may do irrespective of any one secret.
//
// Roles do not cap a delegation and are not how sight of a secret is granted
// — that is the delegation's own job (ADR-0002). There are only two, and the
// list is deliberately short: everything about a particular secret is
// answered by ownership or by a grant.
type Role string

const (
	// Admin is every secret in every Store, and delegation on secrets this
	// caller does not own. The operational bypass.
	Admin Role = "admin"
	// Create may bring new secrets into the inventory, owned by whoever made
	// them. Independent of Admin: somebody who administers the platform need
	// not be the person adding to it, and somebody adding to it need not
	// administer.
	Create Role = "create"
)

// ParseRole reads a role out of a claim value that has already had the
// deployment's prefix stripped. A name nothing here can interpret is refused,
// which is the only safe reading of a word this build does not know.
func ParseRole(name string) (Role, bool) {
	switch Role(name) {
	case Admin, Create:
		return Role(name), true
	}
	return "", false
}

// NewActor builds an actor from what the edge resolved.
func NewActor(handle string, groups []string, roles []Role) Actor {
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}
	roleSet := make(map[Role]struct{}, len(roles))
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}
	return Actor{handle: handle, groups: groupSet, roles: roleSet}
}

// ViaToken is the same actor, arriving on an API token.
func (a Actor) ViaToken(tokenID string) Actor {
	a.viaToken = tokenID
	return a
}

// Handle is the name every service keys and logs on.
func (a Actor) Handle() string {
	return a.handle
}

// TokenID is the public id of the API token this request arrived on, or ""
// for a browser session.
func (a Actor) TokenID() string {
	return a.viaToken
}

// IsAdmin is whether this caller holds the operational bypass.
func (a Actor) IsAdmin() bool {
	_, ok := a.roles[Admin]
	return ok
}

// MayCreate is whether this caller may bring new secrets into the inventory.
func (a Actor) MayCreate() bool {
	if _, ok := a.roles[Admin]; ok {
		return true
	}
	_, ok := a.roles[Create]
	return ok
}

// IsAddressedBy is whether a delegation addressed to `subject` is addressed
// to THIS caller.
//
// A group is matched by exact name. keyway parses no structure out of a
// group name (ADR-0003), so an issuer wanting a grant to a parent group
// to cover the teams inside it emits the ancestors in the claim — and
// then they are ordinary members of this set.
func (a Actor) IsAddressedBy(subject access.Subject) bool {
	if subject.IsUser() {
		return subject.ID() == a.handle
	}
	_, ok := a.groups[subject.ID()]
	return ok
}

// GroupNames is the groups this caller is in, for a console to show. Sorted,
// as the Rust BTreeSet reported them.
func (a Actor) GroupNames() []string {
	names := make([]string, 0, len(a.groups))
	for g := range a.groups {
		names = append(names, g)
	}
	sort.Strings(names)
	return names
}

// RoleNames is the roles this caller holds, by name. Sorted, as the Rust
// BTreeSet reported them.
func (a Actor) RoleNames() []string {
	names := make([]string, 0, len(a.roles))
	for r := range a.roles {
		names = append(names, string(r))
	}
	sort.Strings(names)
	return names
}

// Subjects is every string a delegation could name this caller by.
func (a Actor) Subjects() []access.Subject {
	subjects := make([]access.Subject, 0, 1+len(a.groups))
	subjects = append(subjects, access.User(a.handle))
	for _, g := range a.GroupNames() {
		subjects = append(subjects, access.Group(g))
	}
	return subjects
}

// Ceiling is the highest level this caller holds anywhere, when they hold one
// at all.
//
// Never an answer about a particular secret — that is the access domain —
// only what an account badge says. Two people with the same badge may hold
// nothing in common.
func (a Actor) Ceiling() (access.Level, bool) {
	if a.IsAdmin() {
		return access.Write, true
	}
	return 0, false
}
