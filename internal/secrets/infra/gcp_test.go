package infra

import (
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

func TestAResourceNameReducesToItsLeaf(t *testing.T) {
	// keyway addresses by the leaf; every other backend reports one.
	assert.Equal(t, "db-creds", leaf("projects/acme/secrets/db-creds"))
	assert.Equal(t, "7", leaf("projects/acme/secrets/db-creds/versions/7"))
	assert.Equal(t, "db-creds", leaf("db-creds"))
}

func TestGoogleStatesMapOntoKeywayStates(t *testing.T) {
	assert.Equal(t, entity.VersionEnabled, gcpStateOf(secretmanagerpb.SecretVersion_ENABLED))
	assert.Equal(t, entity.VersionDisabled, gcpStateOf(secretmanagerpb.SecretVersion_DISABLED))
	assert.Equal(t, entity.VersionDestroyed, gcpStateOf(secretmanagerpb.SecretVersion_DESTROYED))
}

func TestAStateThisBuildDoesNotKnowIsNotRevealable(t *testing.T) {
	// Google may add one. Reading it as enabled would offer to reveal a
	// payload that may not be there.
	assert.Equal(t, entity.VersionDestroyed, gcpStateOf(secretmanagerpb.SecretVersion_State(99)))
	assert.Equal(t, entity.VersionDestroyed, gcpStateOf(secretmanagerpb.SecretVersion_STATE_UNSPECIFIED))
}
