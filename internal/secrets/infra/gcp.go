// Google Secret Manager.
//
// Over the official client rather than the REST calls the Rust adapter made:
// in Go the generated client is the well-trodden path, and Application
// Default Credentials come with it — a laptop works after `gcloud auth
// application-default login` and a workload identity works with nothing
// configured. The mapping between what Google returns and what keyway means
// stays here, where it can be read.

package infra

import (
	"context"
	"errors"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// GcpSecretManager serves one Google Cloud project.
type GcpSecretManager struct {
	project string
	client  *secretmanager.Client
}

// NewGcpSecretManager builds a client from Application Default Credentials.
//
// It fails when none can be found.
func NewGcpSecretManager(ctx context.Context, project string) (*GcpSecretManager, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting google credentials: %w", err)
	}
	return &GcpSecretManager{project: project, client: client}, nil
}

// Close releases the client's connections.
func (g *GcpSecretManager) Close() error { return g.client.Close() }

func (g *GcpSecretManager) parent() string {
	return "projects/" + g.project
}

func (g *GcpSecretManager) secretName(name string) string {
	return g.parent() + "/secrets/" + name
}

// gcpError maps what Google reports onto what keyway means. NotFound is an
// answer, not a failure: it is what "no such secret" looks like, and the
// caller reports it identically to a secret outside `select`.
func gcpError(context string, err error) error {
	if status.Code(err) == codes.NotFound {
		return entity.ErrNotFound
	}
	return entity.Backend(context, err)
}

// leaf is the last segment of a Google resource name.
//
// `projects/p/secrets/db-creds` is a full path; keyway addresses by the leaf,
// and every other backend reports one.
func leaf(resource string) string {
	if i := strings.LastIndex(resource, "/"); i >= 0 {
		return resource[i+1:]
	}
	return resource
}

// gcpStateOf is Google's version states, as keyway means them.
func gcpStateOf(state secretmanagerpb.SecretVersion_State) entity.VersionState {
	switch state {
	case secretmanagerpb.SecretVersion_ENABLED:
		return entity.VersionEnabled
	case secretmanagerpb.SecretVersion_DISABLED:
		return entity.VersionDisabled
	default:
		// DESTROYED, and anything a future API adds. A state this build does
		// not understand must not be offered for reveal.
		return entity.VersionDestroyed
	}
}

// List implements entity.SecretManager. It pages through the project rather
// than fanning out a request per secret: this is the first screen of the
// console.
func (g *GcpSecretManager) List(ctx context.Context) ([]entity.Secret, error) {
	var out []entity.Secret
	it := g.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent:   g.parent(),
		PageSize: 1000,
	})
	for {
		listed, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, gcpError("listing google secrets", err)
		}
		out = append(out, entity.Secret{
			Name:        leaf(listed.GetName()),
			Labels:      listed.GetLabels(),
			Annotations: listed.GetAnnotations(),
			// LatestVersion deliberately absent: resolving it costs one call
			// per secret, and a list that makes N requests is a list nobody
			// waits for.
		})
	}
}

// Get implements entity.SecretManager.
func (g *GcpSecretManager) Get(ctx context.Context, name string) (entity.Secret, error) {
	secret, err := g.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: g.secretName(name),
	})
	if err != nil {
		return entity.Secret{}, gcpError("reading a google secret", err)
	}

	// One extra call, and only here: a caller who opened one secret is
	// waiting for one secret.
	versions, err := g.Versions(ctx, name)
	if err != nil {
		return entity.Secret{}, err
	}
	latest := ""
	for _, v := range versions {
		if v.State == entity.VersionEnabled {
			latest = v.ID
			break
		}
	}

	return entity.Secret{
		Name:          leaf(secret.GetName()),
		Labels:        secret.GetLabels(),
		Annotations:   secret.GetAnnotations(),
		LatestVersion: latest,
	}, nil
}

// Versions implements entity.SecretManager. Google returns newest first;
// keyway promises the same.
func (g *GcpSecretManager) Versions(ctx context.Context, name string) ([]entity.Version, error) {
	var out []entity.Version
	it := g.client.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{
		Parent:   g.secretName(name),
		PageSize: 1000,
	})
	for {
		listed, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, gcpError("listing google versions", err)
		}
		out = append(out, entity.Version{
			ID:    leaf(listed.GetName()),
			State: gcpStateOf(listed.GetState()),
		})
	}
}

// Access implements entity.SecretManager.
func (g *GcpSecretManager) Access(ctx context.Context, name, version string) ([]byte, error) {
	if version == "" {
		version = "latest"
	}
	accessed, err := g.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: g.secretName(name) + "/versions/" + version,
	})
	if err != nil {
		return nil, gcpError("reading a google secret's value", err)
	}
	return accessed.GetPayload().GetData(), nil
}

// SetLabels implements entity.SecretManager. It replaces the labels, which
// is what Google's update does with a field mask of `labels` — and what the
// interface promises.
func (g *GcpSecretManager) SetLabels(ctx context.Context, name string, labels entity.Metadata) error {
	_, err := g.client.UpdateSecret(ctx, &secretmanagerpb.UpdateSecretRequest{
		Secret: &secretmanagerpb.Secret{
			Name:   g.secretName(name),
			Labels: labels,
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	})
	if err != nil {
		return gcpError("setting labels on a google secret", err)
	}
	return nil
}

// Create implements entity.SecretManager.
func (g *GcpSecretManager) Create(ctx context.Context, name string, labels entity.Metadata) error {
	_, err := g.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   g.parent(),
		SecretId: name,
		Secret: &secretmanagerpb.Secret{
			Labels: labels,
			// Google requires a replication policy and has no default.
			// Automatic is the one a deployment that has not said otherwise
			// means.
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	})
	if err != nil {
		return gcpError("creating a google secret", err)
	}
	return nil
}

// AddVersion implements entity.SecretManager.
func (g *GcpSecretManager) AddVersion(ctx context.Context, name string, payload []byte) (entity.Version, error) {
	added, err := g.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  g.secretName(name),
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	})
	if err != nil {
		return entity.Version{}, gcpError("adding a google secret version", err)
	}
	return entity.Version{
		ID:    leaf(added.GetName()),
		State: entity.VersionEnabled,
	}, nil
}

// Delete implements entity.SecretManager.
func (g *GcpSecretManager) Delete(ctx context.Context, name string) error {
	err := g.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: g.secretName(name),
	})
	if err != nil {
		return gcpError("deleting a google secret", err)
	}
	return nil
}

var _ entity.SecretManager = (*GcpSecretManager)(nil)
