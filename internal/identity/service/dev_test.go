// Who a dev-mode run acts as, and what it says when the config is wrong.
//
// These decisions used to be made in cmd/api's devActor, where an unknown
// role word was dropped in silence — a console with a missing button and
// nothing anywhere saying why. The outcome is unchanged; what is new is that
// the decision has a home and a voice.

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

func TestADevRunActsAsTheConfiguredUser(t *testing.T) {
	t.Parallel()
	dev := NewDevActor("alice", []string{"admin", "create"}, []string{"SRE"})

	assert.Equal(t, entity.Handle("alice"), dev.Handle)
	actor := dev.Actor()
	assert.Equal(t, "alice", actor.Handle())
	assert.True(t, actor.IsAdmin(),
		"dev mode still makes every authz decision; the dev user simply holds the roles")
	assert.True(t, actor.MayCreate())
	assert.Equal(t, []string{"SRE"}, actor.GroupNames())
}

func TestADevRunWithNoUserConfiguredIsDev(t *testing.T) {
	t.Parallel()
	assert.Equal(t, entity.Handle(DefaultDevHandle), NewDevActor("", nil, nil).Handle)
}

func TestAnUnknownDevRoleGrantsNothing(t *testing.T) {
	t.Parallel()
	// The outcome cmd/api had: the word is dropped, the known ones still
	// hold, and the process starts. Refusing to boot over a misspelling in a
	// local-development setting would be worse.
	dev := NewDevActor("dev", []string{"admn", "create", "root"}, nil)

	actor := dev.Actor()
	assert.False(t, actor.IsAdmin(), "a word this build cannot interpret grants nothing")
	assert.True(t, actor.MayCreate())
	assert.Equal(t, []entity.Role{entity.RoleCreate}, dev.Roles)
}

func TestAnUnusableDevGroupIsDropped(t *testing.T) {
	t.Parallel()
	dev := NewDevActor("dev", nil, []string{"local", "", "  "})
	assert.Equal(t, []entity.GroupName{"local"}, dev.Groups)
}

func TestADevActorHoldsNoRolesByDefault(t *testing.T) {
	t.Parallel()
	// A local run is not an admin unless the config says so — the same
	// authorisation decisions are made either way.
	actor := NewDevActor("dev", nil, nil).Actor()
	assert.False(t, actor.IsAdmin())
	assert.False(t, actor.MayCreate())
}
