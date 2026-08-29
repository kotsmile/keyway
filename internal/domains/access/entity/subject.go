package entity

// Subject is who a delegation is addressed to.
//
// The kind is carried in the value, never inferred from how the name is
// spelled. locker told a group from a person by a leading `/`, which held
// only because Keycloak group paths always start with one; under a generic
// OIDC issuer a claim may yield bare names, and a team called `sre` would
// then be indistinguishable from a person called `sre` (ADR-0003).
//
// It is a two-field value rather than an interface so that two subjects
// compare with ==, which is what the Rust enum's derived Eq gave.
type Subject struct {
	kind string
	id   string
}

// User is a person, by the handle every service keys and logs on.
func User(id string) Subject {
	return Subject{kind: "user", id: id}
}

// Group is a group, named exactly as the issuer's claim spells it. keyway
// parses no structure out of it: an issuer wanting a grant to a parent group
// to cover the teams inside it puts the ancestors in the claim.
func Group(id string) Subject {
	return Subject{kind: "group", id: id}
}

// Kind is the word the `subject_kind` column stores.
func (s Subject) Kind() string {
	return s.kind
}

// ID is the name, without its kind.
func (s Subject) ID() string {
	return s.id
}

// IsUser is whether this subject names a person.
func (s Subject) IsUser() bool {
	return s.kind == "user"
}

func (s Subject) String() string {
	return s.kind + ":" + s.id
}
