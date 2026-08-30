package infra

import (
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

func tag(key, value string) types.Tag {
	return types.Tag{Key: awssdk.String(key), Value: awssdk.String(value)}
}

func TestAwsTagsBecomeKeywayLabels(t *testing.T) {
	// The reason `select` carries a `tags` map: this is the backend that
	// spells labels differently.
	labels := tagsToMetadata([]types.Tag{tag("team", "infra"), tag("keyway", "true")})

	assert.Equal(t, "infra", labels["team"])
	assert.Equal(t, "true", labels["keyway"])
}

func TestLabelsRoundTripThroughTags(t *testing.T) {
	labels := entity.Metadata{"team": "infra"}
	assert.Equal(t, labels, tagsToMetadata(metadataToTags(labels)))
}

func TestNoTagsIsNoLabels(t *testing.T) {
	assert.Empty(t, tagsToMetadata(nil))
	assert.Empty(t, tagsToMetadata([]types.Tag{}))
}

func TestTheCurrentStageIsTheReadableOne(t *testing.T) {
	assert.Equal(t, entity.VersionEnabled, awsStateOf([]string{awsCurrent}))
	assert.Equal(t, entity.VersionDisabled, awsStateOf([]string{awsPrevious}))
}

func TestAVersionCarryingNoStageCannotBeRead(t *testing.T) {
	// AWS has no enabled/disabled flag: a stageless version is pending
	// deletion, and offering to reveal it would fail at the call.
	assert.Equal(t, entity.VersionDestroyed, awsStateOf([]string{}))
	assert.Equal(t, entity.VersionDestroyed, awsStateOf(nil))
}

func TestACustomStageAloneIsNotReadable(t *testing.T) {
	// Somebody's own label is not AWSCURRENT.
	assert.Equal(t, entity.VersionDestroyed, awsStateOf([]string{"MY_STAGE"}))
}

func TestAStringValueIsPreferredOverBytes(t *testing.T) {
	assert.Equal(t, []byte("hunter2"), awsPayloadOf(awssdk.String("hunter2"), []byte("binary")))
}

func TestABinaryValueIsCarriedThrough(t *testing.T) {
	assert.Equal(t, []byte{0x00, 0x01, 0x02}, awsPayloadOf(nil, []byte{0x00, 0x01, 0x02}))
}

func TestASecretWithNeitherReadsAsEmpty(t *testing.T) {
	assert.Empty(t, awsPayloadOf(nil, nil))
}

func TestAMissingResourceIsRecognisedHoweverItIsWorded(t *testing.T) {
	assert.True(t, isAwsNotFound(errors.New("ResourceNotFoundException: no such secret")))
	assert.True(t, isAwsNotFound(&types.ResourceNotFoundException{}))
	assert.False(t, isAwsNotFound(errors.New("AccessDeniedException")))
}
