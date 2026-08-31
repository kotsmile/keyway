// What a person and a group are CALLED.
//
// Both arrive from outside — a claim, a config file, a token row — and both
// are matched EXACTLY wherever they are used: a delegation to the group `sre`
// opens for somebody whose claim says `sre` and for nobody else. That makes
// them the two strings in this system where an empty or accidental value is
// silently a different subject rather than an error, which is what these
// types exist to catch at the door.
//
// Named string types rather than opaque structs, for the reason the secrets
// identifiers give: they must keep landing in the same columns, the same
// sealed cookie and the same JSON they always did.
//
// Note what does NOT use them: the Caller and Actor interfaces the access and
// audit domains declare speak `Handle() string`. identity/entity imports
// access/entity (for Subject and Level), so access/entity cannot import this
// package back without a cycle — the port stays a plain string, deliberately,
// and the conversion happens at that one seam.

package entity

import (
	"errors"
	"strings"
)

// Handle is the name every service keys and logs on.
//
// `preferred_username` from the claim, not the subject: the subject is stable
// but unreadable, and an audit log full of uuids answers nobody's question.
type Handle string

// GroupName is a group exactly as the issuer's claim spells it.
//
// keyway parses no structure out of one (ADR-0003): a bare name, a Keycloak
// path, an LDAP DN are all just this string, and an issuer wanting a grant to
// a parent group to cover the teams inside it emits the ancestors in the
// claim.
type GroupName string

// ErrHandleRequired is nobody at all.
var ErrHandleRequired = errors.New("a handle is required")

// ErrGroupNameRequired is a group name that names no group.
var ErrGroupNameRequired = errors.New("a group name is required")

// NewHandle reads a handle from a claim, a config file or a token row.
//
// Whitespace-only is refused along with empty: a handle is compared exactly
// and recorded in every audit row, and one that renders as nothing is a row
// nobody can act on. Nothing else is refused — what an issuer may put in
// `preferred_username` is the issuer's business, and a handle keyway rejects
// is a person who cannot sign in.
func NewHandle(raw string) (Handle, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ErrHandleRequired
	}
	return Handle(raw), nil
}

// String is the handle as a column, a log line and an audit row spell it.
func (h Handle) String() string { return string(h) }

// NewGroupName reads one group out of a claim.
//
// Refuses the empty name for the same reason a handle refuses it: a
// delegation addressed to "" is one that could only ever be matched by a
// claim that also carries nothing, which is a grant nobody meant to write.
func NewGroupName(raw string) (GroupName, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ErrGroupNameRequired
	}
	return GroupName(raw), nil
}

// String is the group as a grant spells it.
func (g GroupName) String() string { return string(g) }

// GroupNamesOf reads a list of groups, keeping the ones that name a group and
// reporting the rest.
//
// Accept-and-warn rather than refuse-the-lot, because the list comes from an
// issuer's claim and from a deployment's config file: one unusable entry must
// not cost somebody their sign-in, and the caller logs what it dropped so the
// silence is not total.
func GroupNamesOf(raw []string) (groups []GroupName, dropped []string) {
	groups = make([]GroupName, 0, len(raw))
	for _, word := range raw {
		group, err := NewGroupName(word)
		if err != nil {
			dropped = append(dropped, word)
			continue
		}
		groups = append(groups, group)
	}
	return groups, dropped
}

// GroupWords is the plain strings behind a list of groups, for a wire or a
// column that holds them as text.
func GroupWords(groups []GroupName) []string {
	words := make([]string, len(groups))
	for i, group := range groups {
		words[i] = group.String()
	}
	return words
}
