// What a handle and a group name refuse.
//
// Both are matched EXACTLY wherever they are used, which is why an empty one
// is worth refusing at the door: a delegation addressed to "" is a grant
// nobody meant to write, and an audit row whose actor renders as nothing is a
// row nobody can act on.

package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAHandleMustNameSomebody(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw     string
		refused bool
	}{
		"empty":          {raw: "", refused: true},
		"only spaces":    {raw: "   ", refused: true},
		"only a tab":     {raw: "\t", refused: true},
		"a handle":       {raw: "alice"},
		"an email":       {raw: "alice@example.com"},
		"a uuid subject": {raw: "9f2c4e8a-7b31-4d6f-a05e-1c837d942b60"},
		// What an issuer puts in `preferred_username` is the issuer's
		// business; a handle keyway rejects is a person who cannot sign in.
		"a name with a space": {raw: "Alice A."},
		"a unicode handle":    {raw: "алиса"},
		"a windows account":   {raw: `ACME\alice`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			handle, err := NewHandle(tc.raw)
			if tc.refused {
				require.ErrorIs(t, err, ErrHandleRequired)
				return
			}
			require.NoError(t, err)
			// Not trimmed: the handle is compared exactly against what a
			// grant was written to, so keyway must not quietly rewrite it.
			assert.Equal(t, tc.raw, handle.String())
		})
	}
}

func TestAGroupNameMustNameAGroup(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw     string
		refused bool
	}{
		"empty":       {raw: "", refused: true},
		"only spaces": {raw: "  ", refused: true},
		// keyway parses no structure out of a group name (ADR-0003): all of
		// these are one opaque string, matched exactly.
		"a bare name":       {raw: "SRE"},
		"a keycloak path":   {raw: "/SRE/platform"},
		"an ldap dn":        {raw: "cn=sre,ou=groups,dc=acme,dc=com"},
		"a name with space": {raw: "SRE Team"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			group, err := NewGroupName(tc.raw)
			if tc.refused {
				require.ErrorIs(t, err, ErrGroupNameRequired)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.raw, group.String())
		})
	}
}

func TestAnUnusableGroupIsDroppedRatherThanFailingTheClaim(t *testing.T) {
	t.Parallel()
	// One unusable entry in a claim must not cost somebody their sign-in.
	groups, dropped := GroupNamesOf([]string{"SRE", "", "/platform", "   "})
	assert.Equal(t, []GroupName{"SRE", "/platform"}, groups)
	assert.Equal(t, []string{"", "   "}, dropped, "the caller says what it dropped")
}

func TestGroupWordsNeverYieldsNil(t *testing.T) {
	t.Parallel()
	// The `groups` column is NOT NULL: a person in no groups is '{}', never
	// NULL, which is what the Rust server could ever write.
	assert.Equal(t, []string{}, GroupWords(nil))
	assert.Equal(t, []string{"SRE"}, GroupWords([]GroupName{"SRE"}))
}

func TestARoleWordThisBuildDoesNotKnowIsDroppedAndReported(t *testing.T) {
	t.Parallel()
	// Accept-and-warn: a realm may hold roles belonging to other systems
	// entirely, so refusing the whole set would lock somebody out of a
	// console because their realm also runs a wiki. Granting something for a
	// word this build cannot interpret would be worse.
	roles, unknown := ParseRoles([]string{"admin", "superuser", "create", ""})
	assert.Equal(t, []Role{RoleAdmin, RoleCreate}, roles)
	assert.Equal(t, []string{"superuser", ""}, unknown)

	roles, unknown = ParseRoles(nil)
	assert.Empty(t, roles)
	assert.Empty(t, unknown)
}

func TestRoleWordsListsWhatAnErrorCanOffer(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"admin", "create"}, RoleWords())
}
