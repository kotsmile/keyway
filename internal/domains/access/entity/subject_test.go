package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestATeamAndAPersonSharingANameAreDifferentSubjects(t *testing.T) {
	// The scenario ADR-0003 exists for: an Okta claim of ["SRE"] beside a
	// person whose handle is "sre".
	assert.NotEqual(t, User("sre"), Group("sre"))
}

func TestKindAndIDAreReportedSeparately(t *testing.T) {
	group := Group("Engineering")
	assert.Equal(t, "group", group.Kind())
	assert.Equal(t, "Engineering", group.ID())
}

func TestASlashPrefixedNameIsNotTherebyAGroup(t *testing.T) {
	// Nothing reads the shape of a name any more, so a path-shaped handle
	// stays a user.
	user := User("/sre")
	assert.Equal(t, "user", user.Kind())
}
