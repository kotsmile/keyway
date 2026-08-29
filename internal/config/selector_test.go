package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/kotsmile/keyway/internal/domains/secrets/entity"
)

func meta(pairs map[string]string) entity.Metadata {
	return entity.Metadata(pairs)
}

func selector(t *testing.T, text string) Selector {
	t.Helper()
	var s Selector
	require.NoError(t, yaml.Unmarshal([]byte(text), &s), "valid selector")
	return s
}

func TestAnEmptySelectorSelectsEverything(t *testing.T) {
	all := Selector{}
	assert.True(t, all.MatchesAll(meta(nil), meta(nil)))
	assert.True(t, all.IsEmpty())
}

func TestAnEmptySelectorProtectsNothing(t *testing.T) {
	assert.False(t, Selector{}.MatchesAny(meta(map[string]string{"any": "thing"}), meta(nil)))
}

func TestSelectRequiresEveryEntry(t *testing.T) {
	want := selector(t, "labels:\n  team: infra\n  env: prod\n")
	assert.True(t, want.MatchesAll(meta(map[string]string{"team": "infra", "env": "prod"}), meta(nil)))
	assert.False(t, want.MatchesAll(meta(map[string]string{"team": "infra"}), meta(nil)),
		"a partial match must not select")
}

func TestProtectNeedsOnlyOneMarker(t *testing.T) {
	markers := ReconcilerDefaults()
	eso := meta(map[string]string{"reconcile.external-secrets.io/managed": "true"})
	assert.True(t, markers.MatchesAny(eso, meta(nil)))
}

func TestAWildcardMatchesAValueNobodyCanPredict(t *testing.T) {
	markers := ReconcilerDefaults()
	tracked := meta(map[string]string{"argocd.argoproj.io/tracking-id": "payments:apps/Deployment"})
	assert.True(t, markers.MatchesAny(meta(nil), tracked))
}

func TestAWildcardStillNeedsTheKeyPresent(t *testing.T) {
	markers := ReconcilerDefaults()
	assert.False(t, markers.MatchesAny(meta(nil), meta(map[string]string{"other": "value"})))
}

func TestTagsAreMatchedAsLabelsForTheBackendThatSpellsThemSo(t *testing.T) {
	want := selector(t, "tags:\n  keyway: \"true\"\n")
	assert.True(t, want.MatchesAll(meta(map[string]string{"keyway": "true"}), meta(nil)))
}

func TestALabelAndAnAnnotationAreNotInterchangeable(t *testing.T) {
	want := selector(t, "labels:\n  team: infra\n")
	assert.False(t, want.MatchesAll(meta(nil), meta(map[string]string{"team": "infra"})),
		"an annotation must not satisfy a label selector")
}

func TestAMisspelledSelectorKeyIsRefused(t *testing.T) {
	var s Selector
	err := yaml.Unmarshal([]byte("lables:\n  team: infra\n"), &s)
	require.Error(t, err)
}

func TestFirstMatchNamesTheMarker(t *testing.T) {
	markers := ReconcilerDefaults()
	name, found := markers.FirstMatch(meta(map[string]string{"app.kubernetes.io/managed-by": "Helm"}), meta(nil))
	require.True(t, found)
	assert.Equal(t, "app.kubernetes.io/managed-by=Helm", name)

	name, found = markers.FirstMatch(meta(nil), meta(map[string]string{"meta.helm.sh/release-name": "keyway"}))
	require.True(t, found)
	assert.Equal(t, "meta.helm.sh/release-name", name, "a wildcard names only its key")
}
