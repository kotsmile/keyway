// The authorisation spec, ported test for test from the Rust
// access/entity/access_tests.rs. An external test package because the actors
// come from the identity domain, which itself speaks in this package's types.
package entity_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/access/entity"
	identity "github.com/kotsmile/keyway/internal/identity/entity"
)

func now() time.Time {
	return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
}

func alice() identity.Actor {
	return identity.NewActor("alice", []string{"SRE"}, nil)
}

func grant(subject entity.Subject, level entity.Level) entity.Delegation {
	return entity.Delegation{
		ID:        uuid.New(),
		Store:     "gcp-prod",
		Secret:    "db-creds",
		Subject:   subject,
		Level:     level,
		Keys:      nil,
		GrantedBy: "carol",
		GrantedAt: now(),
		ExpiresAt: nil,
		Note:      "",
	}
}

func ownedBy(owner string) *entity.Ownership {
	return &entity.Ownership{
		Store:  "gcp-prod",
		Secret: "db-creds",
		Owner:  owner,
		Since:  now(),
	}
}

func level(t *testing.T, access entity.Access) entity.Level {
	t.Helper()
	require.NotNil(t, access.Level, "a level is held")
	return *access.Level
}

func TestNothingIsTheDefault(t *testing.T) {
	access := entity.Resolve(alice(), nil, nil, now())
	assert.Equal(t, entity.BasisNothing, access.Basis)
	assert.False(t, access.IsVisible(), "an unmentioned secret is not visible")
}

func TestAGrantOpensExactlyWhatItSays(t *testing.T) {
	// ADR-0002: the delegation carries its own level and no role caps it.
	// Alice holds NO roles at all here.
	grants := []entity.Delegation{grant(entity.User("alice"), entity.Write)}
	access := entity.Resolve(alice(), nil, grants, now())

	assert.Equal(t, entity.Write, level(t, access))
	assert.True(t, access.Allows(entity.Read))
	assert.Equal(t, entity.BasisDelegated("alice"), access.Basis)
}

func TestAGroupGrantReachesAMember(t *testing.T) {
	grants := []entity.Delegation{grant(entity.Group("SRE"), entity.Read)}
	access := entity.Resolve(alice(), nil, grants, now())
	assert.Equal(t, entity.Read, level(t, access))
}

func TestAGrantToATeamTheCallerIsNotInOpensNothing(t *testing.T) {
	grants := []entity.Delegation{grant(entity.Group("platform"), entity.Write)}
	assert.False(t, entity.Resolve(alice(), nil, grants, now()).IsVisible())
}

func TestAPersonAndATeamOfTheSameNameAreNotConfused(t *testing.T) {
	// The scenario ADR-0003 exists for. `bob` the person is not in the claim;
	// `bob` the team is. A grant to the person must not reach the member.
	bobTheTeamMember := identity.NewActor("carol", []string{"bob"}, nil)
	toThePerson := []entity.Delegation{grant(entity.User("bob"), entity.Write)}
	assert.False(t, entity.Resolve(bobTheTeamMember, nil, toThePerson, now()).IsVisible())

	toTheTeam := []entity.Delegation{grant(entity.Group("bob"), entity.Write)}
	assert.True(t, entity.Resolve(bobTheTeamMember, nil, toTheTeam, now()).IsVisible())
}

func TestTheBestGrantWinsWhenACallerIsNamedTwice(t *testing.T) {
	// Named directly at read, and through a team at write. The answer is what
	// was granted, not whichever row came back first.
	grants := []entity.Delegation{
		grant(entity.User("alice"), entity.Read),
		grant(entity.Group("SRE"), entity.Write),
	}
	assert.Equal(t, entity.Write, level(t, entity.Resolve(alice(), nil, grants, now())))

	reversed := []entity.Delegation{grants[1], grants[0]}
	assert.Equal(t, entity.Write, level(t, entity.Resolve(alice(), nil, reversed, now())),
		"the answer must not depend on row order")
}

func TestAnExpiredGrantOpensNothing(t *testing.T) {
	expired := grant(entity.User("alice"), entity.Write)
	expiry := now().Add(-time.Second)
	expired.ExpiresAt = &expiry
	assert.False(t, entity.Resolve(alice(), nil, []entity.Delegation{expired}, now()).IsVisible())
}

func TestAGrantExpiringLaterStillOpens(t *testing.T) {
	live := grant(entity.User("alice"), entity.Read)
	expiry := now().Add(time.Hour)
	live.ExpiresAt = &expiry
	assert.True(t, entity.Resolve(alice(), nil, []entity.Delegation{live}, now()).IsVisible())
}

func TestAnOwnerRunsTheirSecretWhateverRoleTheyHold(t *testing.T) {
	// Ownership is orthogonal: alice holds no roles and no grant.
	access := entity.Resolve(alice(), ownedBy("alice"), nil, now())
	assert.Equal(t, entity.Write, level(t, access))
	assert.Equal(t, entity.BasisOwner, access.Basis)
}

func TestOwnershipBySomebodyElseGrantsNothingByItself(t *testing.T) {
	assert.False(t, entity.Resolve(alice(), ownedBy("bob"), nil, now()).IsVisible())
}

func TestAdminOpensEverything(t *testing.T) {
	admin := identity.NewActor("root", nil, []identity.Role{identity.RoleAdmin})
	access := entity.Resolve(admin, ownedBy("alice"), nil, now())
	assert.Equal(t, entity.Write, level(t, access))
	assert.Equal(t, entity.BasisAdmin, access.Basis)
}

func TestAnOwnerWhoIsAlsoAdminIsRecordedAsTheOwner(t *testing.T) {
	// The narrower reason is the truer one, and it is what the audit row says.
	admin := identity.NewActor("alice", nil, []identity.Role{identity.RoleAdmin})
	access := entity.Resolve(admin, ownedBy("alice"), nil, now())
	assert.Equal(t, entity.BasisOwner, access.Basis)
}

func TestTheCreateRoleOpensNoExistingSecret(t *testing.T) {
	// It brings new secrets into the inventory and says nothing about the
	// ones already there.
	creator := identity.NewActor("alice", nil, []identity.Role{identity.RoleCreate})
	assert.False(t, entity.Resolve(creator, nil, nil, now()).IsVisible())
	assert.True(t, creator.MayCreate())
}

func TestAKeyScopedGrantOpensOnlyThoseKeys(t *testing.T) {
	// What makes it safe to bundle a bot's credentials into one secret and
	// still hand out exactly one of them.
	scoped := grant(entity.Group("SRE"), entity.Read)
	scoped.Keys = []string{"db_password"}
	access := entity.Resolve(alice(), nil, []entity.Delegation{scoped}, now())

	assert.True(t, access.AllowsKey(entity.Read, "db_password"))
	assert.False(t, access.AllowsKey(entity.Read, "api_key"))
}

func TestAnUnscopedGrantOpensEveryKeyIncludingLaterOnes(t *testing.T) {
	// The grant names a secret, not a snapshot of it.
	access := entity.Resolve(alice(), nil,
		[]entity.Delegation{grant(entity.User("alice"), entity.Read)}, now())
	assert.True(t, access.AllowsKey(entity.Read, "a-key-added-tomorrow"))
}

func TestGuestSeesTheShapeButNeverTheValue(t *testing.T) {
	access := entity.Resolve(alice(), nil,
		[]entity.Delegation{grant(entity.User("alice"), entity.Guest)}, now())
	assert.True(t, access.IsVisible())
	assert.False(t, access.Allows(entity.Read), "guest must not reveal")
	assert.False(t, access.Allows(entity.Write))
}

func TestAReadGrantDoesNotPermitANewVersion(t *testing.T) {
	access := entity.Resolve(alice(), nil,
		[]entity.Delegation{grant(entity.User("alice"), entity.Read)}, now())
	assert.True(t, access.Allows(entity.Read))
	assert.False(t, access.Allows(entity.Write))
}

func TestATokenCarriesItsHoldersAccessAndNamesItself(t *testing.T) {
	// ADR-0004: a token acts as the person who minted it, and the audit row
	// can say which credential did it.
	via := alice().ViaToken("7f3a9c2e")
	grants := []entity.Delegation{grant(entity.Group("SRE"), entity.Read)}

	assert.Equal(t, entity.Read, level(t, entity.Resolve(via, nil, grants, now())))
	tokenID, viaAPIToken := via.TokenID()
	assert.True(t, viaAPIToken)
	assert.Equal(t, "7f3a9c2e", tokenID)
}

func TestATokenHolderWithNoRememberedGroupsLosesGroupGrants(t *testing.T) {
	// The consequence ADR-0004 names: without a Directory, a token's groups
	// are whatever was remembered at the last sign-in. Empty means a grant to
	// a team is invisible to it.
	forgotten := identity.NewActor("alice", nil, nil).ViaToken("7f3a9c2e")
	grants := []entity.Delegation{grant(entity.Group("SRE"), entity.Read)}
	assert.False(t, entity.Resolve(forgotten, nil, grants, now()).IsVisible())
}
