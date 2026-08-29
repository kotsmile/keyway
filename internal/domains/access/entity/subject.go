// Package entity holds the access domain's core types.
//
// Only what the identity domain leans on is ported so far — Subject and Level
// — the rest of the access domain arrives with its own ticket.
package entity

import "fmt"

// Subject is who a delegation is addressed to.
//
// The kind is carried in the value, never inferred from how the name is
// spelled. locker told a group from a person by a leading `/`, which held
// only because Keycloak group paths always start with one; under a generic
// OIDC issuer a claim may yield bare names, and a team called `sre` would
// then be indistinguishable from a person called `sre` (ADR-0003).
type Subject struct {
	kind string
	id   string
}

// User is a person, by the handle every service keys and logs on.
func User(id string) Subject { return Subject{kind: "user", id: id} }

// Group is a group, named exactly as the issuer's claim spells it. keyway
// parses no structure out of it: an issuer wanting a grant to a parent group
// to cover the teams inside it puts the ancestors in the claim.
func Group(id string) Subject { return Subject{kind: "group", id: id} }

// Kind is the word the `subject_kind` column stores.
func (s Subject) Kind() string { return s.kind }

// ID is the name, without its kind.
func (s Subject) ID() string { return s.id }

// IsUser reports whether this subject is a person.
func (s Subject) IsUser() bool { return s.kind == "user" }

// IsGroup reports whether this subject is a group.
func (s Subject) IsGroup() bool { return s.kind == "group" }

func (s Subject) String() string { return fmt.Sprintf("%s:%s", s.kind, s.id) }
