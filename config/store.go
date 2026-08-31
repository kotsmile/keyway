package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
)

// StoreKind names which SecretManager serves a Store — the `type:` word.
//
// A closed list, because it is not a name a deployment invents: it selects
// one of the implementations compiled into this binary. Refusing an unknown
// one at parse rather than at mount means the message says which word was
// wrong before anything has connected to anything.
type StoreKind string

const (
	// KindKeyway is keyway's own Store, the one backend where keyway holds a
	// payload rather than pointing at somebody else's.
	KindKeyway StoreKind = "keyway"
	KindGcp    StoreKind = "gcp"
	KindYc     StoreKind = "yc"
	KindAws    StoreKind = "aws"
	KindK8s    StoreKind = "k8s"
)

// StoreKinds is every kind this build has, in the order an error lists them.
func StoreKinds() []StoreKind {
	return []StoreKind{KindKeyway, KindGcp, KindYc, KindAws, KindK8s}
}

// UnknownStoreKindError is a `type:` naming a SecretManager this build does
// not have.
//
// Worth refusing to start over: silently serving four of five declared Stores
// is worse than not starting, because nobody notices the fifth is missing.
type UnknownStoreKindError struct {
	Store string
	Kind  string
}

func (e *UnknownStoreKindError) Error() string {
	return fmt.Sprintf("store %q names an unknown type %q; this build has: %s",
		e.Store, e.Kind, joinKinds(StoreKinds()))
}

func joinKinds(kinds []StoreKind) string {
	words := make([]string, len(kinds))
	for i, kind := range kinds {
		words[i] = string(kind)
	}
	return strings.Join(words, ", ")
}

// String is the word the config file spells.
func (k StoreKind) String() string { return string(k) }

// ParseStoreKind reads a `type:` word.
func ParseStoreKind(store, word string) (StoreKind, error) {
	for _, known := range StoreKinds() {
		if StoreKind(word) == known {
			return known, nil
		}
	}
	return "", &UnknownStoreKindError{Store: store, Kind: word}
}

// StoreConfig is one configured backing service.
//
// A Store is configuration; the code behind it is a SecretManager, named by
// `type`. Two Stores may name the same one — a production project and a
// sandbox — and each carries its own scope, its own verbs and its own
// credential.
type StoreConfig struct {
	// ID is the stable handle used in URLs and in the delegations table.
	// Renaming one orphans its grants, so it is chosen once and left alone.
	//
	// The secrets domain's own type: this is the same id a Secret belongs to
	// and a grant is keyed by, and reading it here is where a deployment's
	// word becomes one.
	ID secretsentity.StoreID
	// Kind names which SecretManager serves it; spelled `type` in the file.
	Kind StoreKind
	// Title is what a person picks from the menu. Falls back to the id.
	Title string
	// Allow is what this deployment may do here.
	Allow []Verb
	// Select is which of the backend's secrets this Store exposes at all.
	// Empty selects everything.
	Select Selector
	// Protect is which of those are shown but refused for editing, because a
	// reconciler owns them. Defaults to the External Secrets, Argo CD and
	// Helm markers.
	Protect Selector
	// Settings is everything else in the block: the keys this Store's
	// SecretManager reads and no other. `project` for GCP, `folder` for
	// Lockbox, `namespace` for Kubernetes. They are not in this schema
	// because an adapter is the only thing that can validate them.
	Settings map[string]any
}

// UnmarshalYAML routes the known keys into the schema and keeps the rest for
// the store's adapter to read.
func (s *StoreConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("a store must be a mapping")
	}
	s.Protect = ReconcilerDefaults()
	s.Settings = map[string]any{}
	seen := map[string]bool{}
	// Read as plain words first and turned into their types below: the id has
	// to be known before the kind can be refused by name, and an error that
	// cannot say WHICH store was wrong is an error nobody can act on.
	var id, kind string
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		seen[key.Value] = true
		var err error
		switch key.Value {
		case "id":
			err = value.Decode(&id)
		case "type":
			err = value.Decode(&kind)
		case "title":
			err = value.Decode(&s.Title)
		case "allow":
			err = value.Decode(&s.Allow)
		case "select":
			err = value.Decode(&s.Select)
		case "protect":
			s.Protect = Selector{}
			err = value.Decode(&s.Protect)
		default:
			var setting any
			err = value.Decode(&setting)
			s.Settings[key.Value] = setting
		}
		if err != nil {
			return err
		}
	}
	for _, required := range []string{"id", "type", "allow"} {
		if !seen[required] {
			return fmt.Errorf("a store is missing the %q field", required)
		}
	}

	storeID, err := secretsentity.NewStoreID(id)
	if err != nil {
		return err
	}
	storeKind, err := ParseStoreKind(id, kind)
	if err != nil {
		return err
	}
	s.ID, s.Kind = storeID, storeKind
	return nil
}

// DisplayTitle is the title, or the id when none was given.
func (s StoreConfig) DisplayTitle() string {
	if s.Title == "" {
		return s.ID.String()
	}
	return s.Title
}

// Can is whether one verb is permitted here.
func (s StoreConfig) Can(verb Verb) bool {
	for _, allowed := range s.Allow {
		if allowed == verb {
			return true
		}
	}
	return false
}

// Verb is what a deployment grants on one Store.
//
// Four verbs rather than a read_only flag, because the interesting
// configuration is neither end of that boolean: it is the shared production
// project keyway may read and amend but must never create or destroy in.
type Verb string

const (
	// Read is everything that discloses: list, get, versions, access.
	Read Verb = "read"
	// Edit is changing a secret that exists: a new version, new labels.
	Edit Verb = "edit"
	// Create is bringing a new secret into existence.
	Create Verb = "create"
	// Delete is destroying one. Deliberately not folded into Create: they
	// look like a lifecycle pair, but only one of them can lose data, and
	// letting people add secrets to a project is not thereby letting them
	// remove the ones already there.
	Delete Verb = "delete"
)

// UnmarshalYAML refuses a verb this build does not have.
func (v *Verb) UnmarshalYAML(node *yaml.Node) error {
	var name string
	if err := node.Decode(&name); err != nil {
		return err
	}
	switch Verb(name) {
	case Read, Edit, Create, Delete:
		*v = Verb(name)
		return nil
	default:
		return fmt.Errorf("unknown verb %q, expected read, edit, create or delete", name)
	}
}
