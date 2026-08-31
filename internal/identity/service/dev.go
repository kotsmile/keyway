// Who a run with no issuer acts as.
//
// Dev mode is on precisely when no issuer is configured. Every authorisation
// decision is still made — the dev user simply holds the roles a config file
// gave them — so a local run behaves like production minus the redirect.
//
// The words in that config file are read HERE rather than in cmd/api, which
// is where they used to be read: "an unknown role word is dropped" is a
// decision about what a role means, and cmd is the binding place, not a place
// where meaning is decided. Moving it also made the drop audible — it used to
// happen in silence, so a deployment that misspelled `admn` in dev_roles saw
// a console with no admin and no explanation anywhere.

package service

import (
	"log/slog"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

// DefaultDevHandle is who a dev run acts as when the config names nobody.
const DefaultDevHandle = "dev"

// DevActor is the identity a dev-mode run assumes.
//
// A parsed value, not the config strings: whatever built it has already
// decided which words mean something.
type DevActor struct {
	Handle entity.Handle
	Roles  []entity.Role
	Groups []entity.GroupName
}

// NewDevActor reads one out of a deployment's dev_* configuration.
//
// Accept-and-warn, in both directions:
//
//   - A role word this build cannot interpret is DROPPED, never granted.
//     Refusing to start instead would be defensible for a closed list, but
//     this list is also the shape a realm's roles arrive in, and the two
//     should not disagree about what an unknown word means.
//   - A group name that names no group is dropped the same way.
//
// Both are logged loudly, with the words that were dropped and the words this
// build knows, because the failure mode is otherwise invisible: a console
// where a button is missing and nothing anywhere says why.
func NewDevActor(handle string, roleWords, groupWords []string) DevActor {
	if handle == "" {
		handle = DefaultDevHandle
	}
	// NewHandle can only fail on the empty handle, which the default above has
	// already ruled out.
	name, err := entity.NewHandle(handle)
	if err != nil {
		name = DefaultDevHandle
	}

	roles, unknown := entity.ParseRoles(roleWords)
	if len(unknown) > 0 {
		slog.Warn("dev_roles names roles this build does not have; they grant nothing",
			"unknown", unknown, "known", entity.RoleWords())
	}
	groups, dropped := entity.GroupNamesOf(groupWords)
	if len(dropped) > 0 {
		slog.Warn("dev_groups contains entries that name no group; they are ignored",
			"dropped", len(dropped))
	}

	return DevActor{Handle: name, Roles: roles, Groups: groups}
}

// Actor is who a request with no credential acts as.
func (d DevActor) Actor() entity.Actor {
	return entity.NewActor(d.Handle, d.Groups, d.Roles)
}
