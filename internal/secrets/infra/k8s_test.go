package infra

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

func k8sSecret(data map[string]string, labels map[string]string) *corev1.Secret {
	raw := make(map[string][]byte, len(data))
	for key, value := range data {
		raw[key] = []byte(value)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "db-creds",
			ResourceVersion: "12345",
			Labels:          labels,
		},
		Data: raw,
	}
}

func TestAKubernetesSecretBecomesAKeywayOne(t *testing.T) {
	converted, ok := k8sIntoSecret(k8sSecret(
		map[string]string{"db_password": "hunter2"},
		map[string]string{"team": "infra"},
	))
	require.True(t, ok, "converts")

	assert.Equal(t, entity.SecretName("db-creds"), converted.Name)
	assert.Equal(t, "infra", converted.Labels["team"])
	// The only version id a Kubernetes Secret has.
	assert.Equal(t, entity.VersionID("12345"), converted.LatestVersion)
}

func TestAMultiKeySecretBecomesFlatJSON(t *testing.T) {
	payload, err := k8sPayloadOf(k8sSecret(
		map[string]string{"db_password": "hunter2", "api_key": "abc"}, nil))
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(payload, &parsed))
	assert.Equal(t, "hunter2", parsed["db_password"])
	assert.Equal(t, "abc", parsed["api_key"])
}

func TestALoneValueKeyIsATextSecret(t *testing.T) {
	// What this adapter writes for non-JSON input, so it round-trips.
	payload, err := k8sPayloadOf(k8sSecret(map[string]string{"value": "hunter2"}, nil))
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), payload)
}

func TestK8sTextAndKvBothRoundTrip(t *testing.T) {
	for _, original := range [][]byte{
		[]byte("hunter2"),
		[]byte(`{"db_password":"hunter2","api_key":"abc"}`),
	} {
		back := &corev1.Secret{StringData: k8sBytesToStringData(original)}

		read, err := k8sPayloadOf(back)
		require.NoError(t, err)
		var want map[string]string
		if json.Unmarshal(original, &want) == nil && want != nil {
			var got map[string]string
			require.NoError(t, json.Unmarshal(read, &got))
			assert.Equal(t, want, got)
		} else {
			assert.Equal(t, original, read)
		}
	}
}

func TestASecretWithNoNameIsSkippedRatherThanPanicking(t *testing.T) {
	// Every object from the API server has one, but the type says it is
	// optional and a panic in a listing would take out the console.
	_, ok := k8sIntoSecret(&corev1.Secret{})
	assert.False(t, ok)
}

func TestAnEmptySecretReadsAsEmptyJSON(t *testing.T) {
	payload, err := k8sPayloadOf(&corev1.Secret{})
	require.NoError(t, err)
	assert.Equal(t, []byte("{}"), payload)
}

func TestAReconcilerOwnedSecretCarriesTheMarkerProtectLooksFor(t *testing.T) {
	// Not this package's rule — `protect` lives in the Store — but the labels
	// have to survive conversion for it to see them.
	owned := k8sSecret(
		map[string]string{"db_password": "x"},
		map[string]string{"reconcile.external-secrets.io/managed": "true"},
	)
	converted, ok := k8sIntoSecret(owned)
	require.True(t, ok)

	assert.Equal(t, "true", converted.Labels["reconcile.external-secrets.io/managed"])
}
