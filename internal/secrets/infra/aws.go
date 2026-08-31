// AWS Secrets Manager.
//
// Two things differ from the other backends, and both are mapped here:
//
//  1. AWS spells labels `tags`, which is why the generic `select` carries a
//     `tags` map — this is the backend that reads it.
//  2. Versions are staged, not numbered. AWS identifies a version by an
//     opaque VersionId and marks the current one with the AWSCURRENT stage
//     label, so "latest" is a stage rather than a maximum.
//
// Credentials come from the standard provider chain, so an instance role or
// IRSA works with nothing configured.

package infra

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// awsCurrent is the stage AWS marks the version an unqualified read resolves
// to.
const awsCurrent = "AWSCURRENT"

// awsPrevious is the stage the previous version keeps after a rotation.
const awsPrevious = "AWSPREVIOUS"

// AwsSecretsManager serves one AWS account's Secrets Manager.
type AwsSecretsManager struct {
	client *secretsmanager.Client
}

// NewAwsSecretsManager builds a client from the standard provider chain. An
// empty region takes the chain's own.
func NewAwsSecretsManager(ctx context.Context, region string) (*AwsSecretsManager, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("loading aws configuration: %w", err)
	}
	return &AwsSecretsManager{client: secretsmanager.NewFromConfig(cfg)}, nil
}

// tagsToMetadata converts: AWS reports tags as a list of pairs; keyway means
// a map.
func tagsToMetadata(tags []types.Tag) entity.Metadata {
	out := entity.Metadata{}
	for _, tag := range tags {
		if tag.Key == nil || tag.Value == nil {
			continue
		}
		out[*tag.Key] = *tag.Value
	}
	return out
}

func metadataToTags(labels entity.Metadata) []types.Tag {
	out := make([]types.Tag, 0, len(labels))
	for key, value := range labels {
		out = append(out, types.Tag{
			Key:   awssdk.String(key),
			Value: awssdk.String(value),
		})
	}
	return out
}

// awsStateOf is what a version's stage labels mean.
//
// AWS has no per-version enabled/disabled flag: a version either carries a
// stage or it does not, and one carrying none is pending deletion and cannot
// be read. So AWSCURRENT and AWSPREVIOUS are readable and everything else is
// not — which is the honest mapping, since offering to reveal a stageless
// version would fail at the call.
func awsStateOf(stages []string) entity.VersionState {
	for _, stage := range stages {
		if stage == awsCurrent {
			return entity.VersionEnabled
		}
	}
	for _, stage := range stages {
		if stage == awsPrevious {
			return entity.VersionDisabled
		}
	}
	return entity.VersionDestroyed
}

// awsPayloadOf converts: AWS carries a value as either a string or bytes.
// keyway's interface carries bytes, and a string is the common case.
func awsPayloadOf(secretString *string, secretBinary []byte) []byte {
	if secretString != nil {
		return []byte(*secretString)
	}
	return secretBinary
}

// isAwsNotFound is whether an AWS failure means "no such secret".
func isAwsNotFound(err error) bool {
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return true
	}
	// The SDK's typed errors do not cover every path, so this also reads the
	// rendered form — the same fallback the Rust adapter relied on.
	return err != nil && strings.Contains(err.Error(), "ResourceNotFound")
}

func awsError(context string, err error) error {
	if isAwsNotFound(err) {
		return entity.ErrNotFound
	}
	return entity.Backend(context, err)
}

// List implements entity.SecretManager.
func (a *AwsSecretsManager) List(ctx context.Context) ([]entity.Secret, error) {
	var out []entity.Secret
	pages := secretsmanager.NewListSecretsPaginator(a.client, &secretsmanager.ListSecretsInput{
		MaxResults: awssdk.Int32(100),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, awsError("listing aws secrets", err)
		}
		for _, entry := range page.SecretList {
			if entry.Name == nil {
				continue
			}
			out = append(out, entity.Secret{
				Name:   entity.SecretName(*entry.Name),
				Labels: tagsToMetadata(entry.Tags),
				// AWS does not report a version id in a listing, and
				// resolving one costs a call per secret.
			})
		}
	}
	return out, nil
}

// Get implements entity.SecretManager.
func (a *AwsSecretsManager) Get(ctx context.Context, name entity.SecretName) (entity.Secret, error) {
	described, err := a.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: awssdk.String(name.String()),
	})
	if err != nil {
		return entity.Secret{}, awsError("reading an aws secret", err)
	}

	// The stage map is version id → stages, so the current one is found by
	// looking for the label rather than by ordering.
	var current entity.VersionID
	for id, stages := range described.VersionIdsToStages {
		for _, stage := range stages {
			if stage == awsCurrent {
				current = entity.VersionID(id)
			}
		}
	}

	describedName := name
	if described.Name != nil {
		describedName = entity.SecretName(*described.Name)
	}
	return entity.Secret{
		Name:          describedName,
		Labels:        tagsToMetadata(described.Tags),
		LatestVersion: current,
	}, nil
}

// Versions implements entity.SecretManager.
func (a *AwsSecretsManager) Versions(ctx context.Context, name entity.SecretName) ([]entity.Version, error) {
	listed, err := a.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
		SecretId:          awssdk.String(name.String()),
		IncludeDeprecated: awssdk.Bool(true),
	})
	if err != nil {
		return nil, awsError("listing aws versions", err)
	}

	type dated struct {
		created int64
		version entity.Version
	}
	versions := make([]dated, 0, len(listed.Versions))
	for _, v := range listed.Versions {
		if v.VersionId == nil {
			continue
		}
		created := int64(math.MinInt64)
		if v.CreatedDate != nil {
			created = v.CreatedDate.Unix()
		}
		versions = append(versions, dated{
			created: created,
			version: entity.Version{
				ID:    entity.VersionID(*v.VersionId),
				State: awsStateOf(v.VersionStages),
			},
		})
	}

	// Newest first, which is what the interface promises and what AWS does
	// not guarantee.
	sort.SliceStable(versions, func(i, j int) bool { return versions[i].created > versions[j].created })
	out := make([]entity.Version, 0, len(versions))
	for _, v := range versions {
		out = append(out, v.version)
	}
	return out, nil
}

// Access implements entity.SecretManager.
func (a *AwsSecretsManager) Access(ctx context.Context, name entity.SecretName, version entity.VersionID) ([]byte, error) {
	input := &secretsmanager.GetSecretValueInput{SecretId: awssdk.String(name.String())}
	if !version.IsLatest() {
		input.VersionId = awssdk.String(version.String())
	} else {
		// Explicit rather than implied: the default is AWSCURRENT anyway, but
		// saying so is what makes the mapping legible.
		input.VersionStage = awssdk.String(awsCurrent)
	}

	value, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, awsError("reading an aws secret's value", err)
	}
	return awsPayloadOf(value.SecretString, value.SecretBinary), nil
}

// SetLabels implements entity.SecretManager. It replaces the tags, which is
// what the interface promises — so tags AWS holds and the caller did not
// send are removed.
func (a *AwsSecretsManager) SetLabels(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	existing, err := a.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: awssdk.String(name.String()),
	})
	if err != nil {
		return awsError("reading an aws secret's tags", err)
	}

	var stale []string
	for key := range tagsToMetadata(existing.Tags) {
		if _, kept := labels[key]; !kept {
			stale = append(stale, key)
		}
	}
	if len(stale) > 0 {
		if _, err := a.client.UntagResource(ctx, &secretsmanager.UntagResourceInput{
			SecretId: awssdk.String(name.String()),
			TagKeys:  stale,
		}); err != nil {
			return awsError("removing aws tags", err)
		}
	}

	if len(labels) > 0 {
		if _, err := a.client.TagResource(ctx, &secretsmanager.TagResourceInput{
			SecretId: awssdk.String(name.String()),
			Tags:     metadataToTags(labels),
		}); err != nil {
			return awsError("setting aws tags", err)
		}
	}
	return nil
}

// Create implements entity.SecretManager.
func (a *AwsSecretsManager) Create(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	if _, err := a.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name: awssdk.String(name.String()),
		Tags: metadataToTags(labels),
	}); err != nil {
		return awsError("creating an aws secret", err)
	}
	return nil
}

// AddVersion implements entity.SecretManager.
func (a *AwsSecretsManager) AddVersion(ctx context.Context, name entity.SecretName, payload []byte) (entity.Version, error) {
	// Lossy, like the Rust adapter's from_utf8_lossy: AWS's string field
	// cannot carry invalid UTF-8, and refusing the whole write over one bad
	// byte would be worse.
	written, err := a.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     awssdk.String(name.String()),
		SecretString: awssdk.String(strings.ToValidUTF8(string(payload), "�")),
	})
	if err != nil {
		return entity.Version{}, awsError("adding an aws secret version", err)
	}

	var id entity.VersionID
	if written.VersionId != nil {
		id = entity.VersionID(*written.VersionId)
	}
	return entity.Version{ID: id, State: entity.VersionEnabled}, nil
}

// Delete implements entity.SecretManager. It destroys immediately rather
// than scheduling.
//
// AWS defaults to a recovery window, which sounds safer and is not what a
// caller of Delete asked for: a scheduled secret still occupies its name, so
// recreating it fails and the console shows a deletion that did not happen.
func (a *AwsSecretsManager) Delete(ctx context.Context, name entity.SecretName) error {
	if _, err := a.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   awssdk.String(name.String()),
		ForceDeleteWithoutRecovery: awssdk.Bool(true),
	}); err != nil {
		return awsError("deleting an aws secret", err)
	}
	return nil
}

var _ entity.SecretManager = (*AwsSecretsManager)(nil)
