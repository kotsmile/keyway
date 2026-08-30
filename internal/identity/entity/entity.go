// Package entity holds the identity domain's core types.
package entity

import (
	"sort"
	"time"

	access "github.com/kotsmile/keyway/internal/access/entity"
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
type Role int

const (
	// RoleAdmin is every secret in every Store, and delegation on secrets
	// this caller does not own. The operational bypass.
	RoleAdmin Role = iota
	// RoleCreate may bring new secrets into the inventory, owned by whoever
	// made them. Independent of Admin: somebody who administers the platform
	// need not be the person adding to it, and somebody adding to it need not
	// administer.
	RoleCreate
)

// String is the role name as a claim spells it, without the configured
// prefix.
func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleCreate:
		return "create"
	}
	return ""
}

// ParseRole reads a role out of a claim value that has already had the
// deployment's prefix stripped. A name nothing here can interpret is refused,
// which is the only safe reading of a word this build does not know.
func ParseRole(name string) (Role, bool) {
	switch name {
	case "admin":
		return RoleAdmin, true
	case "create":
		return RoleCreate, true
	}
	return 0, false
}

// NewActor builds an actor from a handle, the groups they are in and the
// roles they hold. Duplicates collapse: membership is a set, not a list.
func NewActor(handle string, groups []string, roles []Role) Actor {
	actor := Actor{
		handle: handle,
		groups: make(map[string]struct{}, len(groups)),
		roles:  make(map[Role]struct{}, len(roles)),
	}
	for _, group := range groups {
		actor.groups[group] = struct{}{}
	}
	for _, role := range roles {
		actor.roles[role] = struct{}{}
	}
	return actor
}

// ViaToken is the same actor, arriving on an API token.
func (a Actor) ViaToken(tokenID string) Actor {
	a.viaToken = tokenID
	return a
}

// Handle is the name every service keys and logs on.
func (a Actor) Handle() string { return a.handle }

// TokenID is the public id of the API token this request arrived on, and
// false for a browser session.
func (a Actor) TokenID() (string, bool) { return a.viaToken, a.viaToken != "" }

// IsAdmin reports whether the caller holds the admin role.
func (a Actor) IsAdmin() bool {
	_, ok := a.roles[RoleAdmin]
	return ok
}

// MayCreate reports whether the caller may bring new secrets into the
// inventory.
func (a Actor) MayCreate() bool {
	if a.IsAdmin() {
		return true
	}
	_, ok := a.roles[RoleCreate]
	return ok
}

// IsAddressedBy is whether a delegation addressed to subject is addressed to
// THIS caller.
//
// A group is matched by exact name. keyway parses no structure out of a
// group name (ADR-0003), so an issuer wanting a grant to a parent group to
// cover the teams inside it emits the ancestors in the claim — and then they
// are ordinary members of this set.
func (a Actor) IsAddressedBy(subject access.Subject) bool {
	if subject.IsUser() {
		return subject.ID() == a.handle
	}
	_, ok := a.groups[subject.ID()]
	return ok
}

// GroupNames is the groups this caller is in, for a console to show.
func (a Actor) GroupNames() []string {
	names := make([]string, 0, len(a.groups))
	for group := range a.groups {
		names = append(names, group)
	}
	sort.Strings(names)
	return names
}

// RoleNames is the roles this caller holds, by name.
func (a Actor) RoleNames() []string {
	roles := make([]Role, 0, len(a.roles))
	for role := range a.roles {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.String()
	}
	return names
}

// Subjects is every string a delegation could name this caller by.
func (a Actor) Subjects() []access.Subject {
	subjects := make([]access.Subject, 0, 1+len(a.groups))
	subjects = append(subjects, access.User(a.handle))
	for _, group := range a.GroupNames() {
		subjects = append(subjects, access.Group(group))
	}
	return subjects
}

// Ceiling is the highest level this caller holds anywhere.
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

// RememberedUser is what keyway remembers about a person between sign-ins.
//
// The groups claim as it stood at their last sign-in, so an API token —
// which carries no claim of its own — can act as its holder in full
// (ADR-0004).
type RememberedUser struct {
	Handle    string
	Groups    []string
	Email     string
	Name      string
	LastLogin time.Time
}
