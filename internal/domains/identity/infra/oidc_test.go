package infra

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func claims(t *testing.T, text string) map[string]any {
	t.Helper()
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &parsed))
	return parsed
}

func TestAFlatClaimIsRead(t *testing.T) {
	c := claims(t, `{"groups": ["SRE", "platform"]}`)
	assert.Equal(t, []string{"SRE", "platform"}, stringsAt(c, "groups"))
}

func TestANestedClaimIsReadByPath(t *testing.T) {
	// Keycloak's shape. A flat lookup would find nothing and grant nothing,
	// silently.
	c := claims(t, `{"realm_access": {"roles": ["keyway:admin"]}}`)
	assert.Equal(t, []string{"keyway:admin"}, stringsAt(c, "realm_access.roles"))
}

func TestASingleStringClaimIsOneValue(t *testing.T) {
	c := claims(t, `{"groups": "SRE"}`)
	assert.Equal(t, []string{"SRE"}, stringsAt(c, "groups"))
}

func TestAMissingClaimIsEmptyRatherThanAnError(t *testing.T) {
	// Somebody with no groups is not a failure, and refusing to sign them in
	// would make "no teams yet" indistinguishable from a broken issuer.
	c := claims(t, `{"sub": "abc"}`)
	assert.Empty(t, stringsAt(c, "groups"))
	assert.Empty(t, stringsAt(c, "realm_access.roles"))
}

func TestAClaimOfTheWrongShapeIsEmpty(t *testing.T) {
	c := claims(t, `{"groups": {"not": "a list"}}`)
	assert.Empty(t, stringsAt(c, "groups"))
}
