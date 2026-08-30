// Kubernetes Secrets.
//
// The backend where `select` is not really optional. A cluster namespace is
// full of service-account tokens, TLS material and Helm release state, and
// almost none of it belongs in a secrets console — so a Store with no
// selector shows hundreds of objects nobody wanted.
//
// It is also the backend `protect` exists for. External Secrets' whole job is
// syncing secrets *into* a cluster, so without protection keyway would offer
// to edit exactly the objects a reconcile loop overwrites — and the edit
// would disappear on the next sync with nothing to show for it.

package infra

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// k8sRevision is keyway's own annotation recording which revision a Secret is
// on.
//
// Kubernetes has no version history: a Secret has one value, and writing a
// new one replaces it. keyway reports the resourceVersion as the version id,
// which is honest — it changes on every write and identifies the current
// state — but it cannot offer older ones, because they do not exist.
const k8sRevision = "keyway.io/revision"

// KubernetesSecrets serves one cluster namespace.
type KubernetesSecrets struct {
	api       corev1client.SecretInterface
	namespace string
}

// NewKubernetesSecrets connects using the ambient config: a kubeconfig on a
// laptop, the service account inside a pod.
//
// It fails when no cluster configuration can be found.
func NewKubernetesSecrets(namespace string) (*KubernetesSecrets, error) {
	restConfig, err := ambientKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("finding a cluster configuration: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building a kubernetes client: %w", err)
	}
	return &KubernetesSecrets{
		api:       clientset.CoreV1().Secrets(namespace),
		namespace: namespace,
	}, nil
}

func ambientKubeConfig() (*rest.Config, error) {
	if inCluster, err := rest.InClusterConfig(); err == nil {
		return inCluster, nil
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

// Namespace is the namespace this Store serves.
func (k *KubernetesSecrets) Namespace() string { return k.namespace }

// k8sIntoSecret turns a Kubernetes Secret into keyway's shape, or false for
// an object with no name — every object from the API server has one, but the
// type says it is optional and a panic in a listing would take out the
// console.
func k8sIntoSecret(secret *corev1.Secret) (entity.Secret, bool) {
	if secret.Name == "" {
		return entity.Secret{}, false
	}
	return entity.Secret{
		Name:        secret.Name,
		Labels:      secret.Labels,
		Annotations: secret.Annotations,
		// resourceVersion changes on every write and identifies the current
		// state. It is the only version id a Kubernetes Secret has.
		LatestVersion: secret.ResourceVersion,
	}, true
}

// k8sPayloadOf is the payload, as flat JSON.
//
// The whole `data` map becomes the payload, because a Kubernetes Secret is
// natively key/value and flat JSON is the shape every kv path in keyway
// expects. Kubernetes stores values base64-encoded on the wire; the client
// decodes them, so what arrives here is already raw.
func k8sPayloadOf(secret *corev1.Secret) ([]byte, error) {
	m := map[string]string{}
	for key, value := range secret.Data {
		m[key] = string(value)
	}
	// `stringData` is write-only in the API and normally absent on read, but
	// an object constructed by a controller may carry it.
	for key, value := range secret.StringData {
		m[key] = value
	}

	if len(m) == 1 {
		if only, ok := m["value"]; ok {
			return []byte(only), nil
		}
	}
	encoded, err := marshalFlat(m)
	if err != nil {
		return nil, entity.Backend("encoding a k8s payload", err)
	}
	return encoded, nil
}

// k8sBytesToStringData is the inverse: what to write.
func k8sBytesToStringData(payload []byte) map[string]string {
	return flatKV(payload)
}

func k8sError(context string, err error) error {
	if apierrors.IsNotFound(err) {
		return entity.ErrNotFound
	}
	return entity.Backend(context, err)
}

// List implements entity.SecretManager.
func (k *KubernetesSecrets) List(ctx context.Context) ([]entity.Secret, error) {
	// Unfiltered here on purpose: `select` is applied by the Store, in one
	// place, so a selector cannot be honoured by one backend and forgotten by
	// another.
	listed, err := k.api.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, k8sError("listing kubernetes secrets", err)
	}

	out := make([]entity.Secret, 0, len(listed.Items))
	for i := range listed.Items {
		if secret, ok := k8sIntoSecret(&listed.Items[i]); ok {
			out = append(out, secret)
		}
	}
	return out, nil
}

// Get implements entity.SecretManager.
func (k *KubernetesSecrets) Get(ctx context.Context, name string) (entity.Secret, error) {
	fetched, err := k.api.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return entity.Secret{}, k8sError("reading a kubernetes secret", err)
	}
	secret, ok := k8sIntoSecret(fetched)
	if !ok {
		return entity.Secret{}, entity.ErrNotFound
	}
	return secret, nil
}

// Versions implements entity.SecretManager. One version, always.
//
// Kubernetes keeps no history: a Secret has one value and a write replaces
// it. Reporting a single version is the honest answer — inventing a series
// would promise older values that cannot be fetched.
func (k *KubernetesSecrets) Versions(ctx context.Context, name string) ([]entity.Version, error) {
	secret, err := k.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	return []entity.Version{{
		ID:    secret.LatestVersion,
		State: entity.VersionEnabled,
	}}, nil
}

// Access implements entity.SecretManager.
func (k *KubernetesSecrets) Access(ctx context.Context, name, version string) ([]byte, error) {
	fetched, err := k.api.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, k8sError("reading a kubernetes secret's value", err)
	}

	// Asking for anything but the current revision is a request Kubernetes
	// cannot serve, and saying so beats quietly returning the current one
	// under a version id the caller did not ask for.
	if version != "" && fetched.ResourceVersion != version {
		return nil, &entity.NoSuchVersionError{Version: version}
	}
	return k8sPayloadOf(fetched)
}

// SetLabels implements entity.SecretManager.
func (k *KubernetesSecrets) SetLabels(ctx context.Context, name string, labels entity.Metadata) error {
	// A merge patch with the full map, which is what the Rust adapter sent —
	// a strategic merge would only ever add.
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": labels},
	})
	if err != nil {
		return entity.Backend("setting labels on a kubernetes secret", err)
	}
	if _, err := k.api.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return k8sError("setting labels on a kubernetes secret", err)
	}
	return nil
}

// Create implements entity.SecretManager.
func (k *KubernetesSecrets) Create(ctx context.Context, name string, labels entity.Metadata) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: k.namespace,
			Labels:    labels,
		},
	}
	if _, err := k.api.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return k8sError("creating a kubernetes secret", err)
	}
	return nil
}

// AddVersion implements entity.SecretManager.
func (k *KubernetesSecrets) AddVersion(ctx context.Context, name string, payload []byte) (entity.Version, error) {
	patch, err := json.Marshal(map[string]any{
		// `stringData` rather than `data`, so Kubernetes does the base64
		// encoding and keyway cannot get it wrong.
		"stringData": k8sBytesToStringData(payload),
		"metadata":   map[string]any{"annotations": map[string]string{k8sRevision: "keyway"}},
	})
	if err != nil {
		return entity.Version{}, entity.Backend("writing a kubernetes secret", err)
	}

	written, err := k.api.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return entity.Version{}, k8sError("writing a kubernetes secret", err)
	}
	return entity.Version{
		ID:    written.ResourceVersion,
		State: entity.VersionEnabled,
	}, nil
}

// Delete implements entity.SecretManager.
func (k *KubernetesSecrets) Delete(ctx context.Context, name string) error {
	if err := k.api.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return k8sError("deleting a kubernetes secret", err)
	}
	return nil
}

var _ entity.SecretManager = (*KubernetesSecrets)(nil)
