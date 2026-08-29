package config

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kotsmile/keyway/internal/domains/secrets/entity"
)

// Selector is a set of labels, annotations or tags to match a secret's
// metadata against.
//
// One type serves both `select` and `protect`, but they ask different
// questions of it, so it has two methods rather than one. `select` is a
// filter — every entry must match, as a Kubernetes label selector does.
// `protect` is a set of markers — any one matching is enough, because a
// secret owned by External Secrets and a secret owned by Helm are both
// somebody else's to edit.
type Selector struct {
	Labels      map[string]string
	Annotations map[string]string
	// Tags is how AWS spells labels. The generic `select` is mapped per
	// backend, and this is where that mapping is spelled for the one that
	// differs.
	Tags map[string]string
}

// UnmarshalYAML refuses unknown keys: `lables:` should not read as "no labels
// configured" in a file that gates who sees what.
func (s *Selector) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("a selector must be a mapping of labels, annotations or tags")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch key := node.Content[i].Value; key {
		case "labels", "annotations", "tags":
		default:
			return fmt.Errorf("a selector has no field %q, expected labels, annotations or tags", key)
		}
	}
	var plain struct {
		Labels      map[string]string `yaml:"labels"`
		Annotations map[string]string `yaml:"annotations"`
		Tags        map[string]string `yaml:"tags"`
	}
	if err := node.Decode(&plain); err != nil {
		return err
	}
	s.Labels, s.Annotations, s.Tags = plain.Labels, plain.Annotations, plain.Tags
	return nil
}

// anyValue matches a key whatever it holds, for a marker whose value is an id
// nobody can predict (argocd.argoproj.io/tracking-id).
const anyValue = "*"

// IsEmpty is whether this selector asks for anything at all.
func (s Selector) IsEmpty() bool {
	return len(s.Labels) == 0 && len(s.Annotations) == 0 && len(s.Tags) == 0
}

// MatchesAll is whether metadata satisfies EVERY entry — the `select`
// question.
//
// An empty selector selects everything, which is what a Store that has said
// nothing about scoping means.
func (s Selector) MatchesAll(labels, annotations entity.Metadata) bool {
	for _, e := range s.entries() {
		if !matchesOne(e, labels, annotations) {
			return false
		}
	}
	return true
}

// MatchesAny is whether metadata satisfies ANY entry — the `protect`
// question.
//
// An empty selector protects nothing, so a Store with no `protect` block
// behaves as though the concept did not exist.
func (s Selector) MatchesAny(labels, annotations entity.Metadata) bool {
	for _, e := range s.entries() {
		if matchesOne(e, labels, annotations) {
			return true
		}
	}
	return false
}

// FirstMatch is the first entry metadata satisfies, as `key=value` — what a
// refusal names so its reader knows which tool to go and look at.
func (s Selector) FirstMatch(labels, annotations entity.Metadata) (string, bool) {
	for _, e := range s.entries() {
		if matchesOne(e, labels, annotations) {
			if e.want == anyValue {
				return e.key, true
			}
			return e.key + "=" + e.want, true
		}
	}
	return "", false
}

type entryKind int

const (
	labelEntry entryKind = iota
	annotationEntry
)

type selectorEntry struct {
	kind      entryKind
	key, want string
}

// entries lists every entry in a fixed order — labels, then tags, then
// annotations, each sorted by key — so FirstMatch names the same marker on
// every run.
func (s Selector) entries() []selectorEntry {
	out := make([]selectorEntry, 0, len(s.Labels)+len(s.Tags)+len(s.Annotations))
	for _, kv := range sorted(s.Labels) {
		out = append(out, selectorEntry{labelEntry, kv[0], kv[1]})
	}
	for _, kv := range sorted(s.Tags) {
		out = append(out, selectorEntry{labelEntry, kv[0], kv[1]})
	}
	for _, kv := range sorted(s.Annotations) {
		out = append(out, selectorEntry{annotationEntry, kv[0], kv[1]})
	}
	return out
}

func sorted(m map[string]string) [][2]string {
	out := make([][2]string, 0, len(m))
	for k, v := range m {
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

func matchesOne(e selectorEntry, labels, annotations entity.Metadata) bool {
	source := labels
	if e.kind == annotationEntry {
		source = annotations
	}
	have, present := source[e.key]
	if !present {
		return false
	}
	return e.want == anyValue || have == e.want
}

// ReconcilerDefaults is the markers keyway refuses to edit unless a
// deployment says otherwise: External Secrets, Argo CD and Helm. They are
// defaults rather than hard-coded knowledge, so a site using different
// tooling overrides them.
func ReconcilerDefaults() Selector {
	return Selector{
		Labels: map[string]string{
			"reconcile.external-secrets.io/managed": "true",
			"app.kubernetes.io/managed-by":          "Helm",
		},
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": anyValue,
			"meta.helm.sh/release-name":      anyValue,
		},
	}
}
