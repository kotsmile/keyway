package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	access "github.com/kotsmile/keyway/internal/access/entity"
)

func TestADelegationToTheHandleAddressesTheCaller(t *testing.T) {
	actor := NewActor("alice", []string{"SRE"}, nil)
	assert.True(t, actor.IsAddressedBy(access.User("alice")))
	assert.False(t, actor.IsAddressedBy(access.User("bob")))
}

func TestAGroupIsMatchedByExactNameOnly(t *testing.T) {
	// keyway parses no structure out of a group name (ADR-0003): an issuer
	// wanting a grant to a parent group to cover the teams inside it emits
	// the ancestors in the claim.
	actor := NewActor("alice", []string{"/SRE/platform"}, nil)
	assert.True(t, actor.IsAddressedBy(access.Group("/SRE/platform")))
	assert.False(t, actor.IsAddressedBy(access.Group("/SRE")),
		"an ancestor not in the claim is not a membership")
}

func TestAGroupSharingTheHandleDoesNotAddressTheCaller(t *testing.T) {
	// A team called `sre` and a person whose handle is `sre` are two
	// different subjects (ADR-0003).
	actor := NewActor("sre", nil, nil)
	assert.True(t, actor.IsAddressedBy(access.User("sre")))
	assert.False(t, actor.IsAddressedBy(access.Group("sre")))
}

func TestAdminAndCreateAreIndependentRoles(t *testing.T) {
	admin := NewActor("alice", nil, []Role{RoleAdmin})
	assert.True(t, admin.IsAdmin())
	assert.True(t, admin.MayCreate(), "admin subsumes create")

	creator := NewActor("bob", nil, []Role{RoleCreate})
	assert.False(t, creator.IsAdmin(), "adding to the platform is not administering it")
	assert.True(t, creator.MayCreate())

	nobody := NewActor("carol", nil, nil)
	assert.False(t, nobody.IsAdmin())
	assert.False(t, nobody.MayCreate())
}

func TestSubjectsListsTheHandleThenEveryGroup(t *testing.T) {
	actor := NewActor("alice", []string{"platform", "SRE"}, nil)
	assert.Equal(t, []access.Subject{
		access.User("alice"),
		access.Group("SRE"),
		access.Group("platform"),
	}, actor.Subjects())
}

func TestOnlyAnAdminHasACeiling(t *testing.T) {
	// Never an answer about a particular secret — only what an account badge
	// says.
	_, ok := NewActor("alice", nil, nil).Ceiling()
	assert.False(t, ok)

	level, ok := NewActor("alice", nil, []Role{RoleAdmin}).Ceiling()
	require.True(t, ok)
	assert.Equal(t, access.Write, level)
}

func TestViaTokenNamesTheCredentialThatActed(t *testing.T) {
	// So an audit row can say WHICH credential acted, not merely which
	// account.
	session := NewActor("alice", nil, nil)
	_, viaToken := session.TokenID()
	assert.False(t, viaToken)

	bot := session.ViaToken("7f3a9c2e")
	id, viaToken := bot.TokenID()
	require.True(t, viaToken)
	assert.Equal(t, "7f3a9c2e", id)
	assert.Equal(t, "alice", bot.Handle(), "the token acts as the person who minted it")
}

func TestARoleNameNobodyKnowsIsRefused(t *testing.T) {
	// The only safe reading of a word this build does not know.
	_, known := ParseRole("superuser")
	assert.False(t, known)

	for _, role := range []Role{RoleAdmin, RoleCreate} {
		parsed, known := ParseRole(role.String())
		require.True(t, known)
		assert.Equal(t, role, parsed)
	}
}

func TestGroupAndRoleNamesAreSortedAndDeduplicated(t *testing.T) {
	// Membership is a set, not a list: the order a claim spelled it in
	// carries no meaning, and a console wants a stable one.
	actor := NewActor("alice", []string{"platform", "SRE", "platform"},
		[]Role{RoleCreate, RoleAdmin, RoleCreate})
	assert.Equal(t, []string{"SRE", "platform"}, actor.GroupNames())
	assert.Equal(t, []string{"admin", "create"}, actor.RoleNames())
}
