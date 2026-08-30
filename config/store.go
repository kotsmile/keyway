package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// StoreConfig is one configured backing service.
//
// A Store is configuration; the code behind it is a SecretManager, named by
// `type`. Two Stores may name the same one — a production project and a
// sandbox — and each carries its own scope, its own verbs and its own
// credential.
type StoreConfig struct {
	// ID is the stable handle used in URLs and in the delegations table.
	// Renaming one orphans its grants, so it is chosen once and left alone.
	ID string
	// Kind names which SecretManager serves it; spelled `type` in the file.
	Kind string
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
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		seen[key.Value] = true
		var err error
		switch key.Value {
		case "id":
			err = value.Decode(&s.ID)
		case "type":
			err = value.Decode(&s.Kind)
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
	return nil
}

// DisplayTitle is the title, or the id when none was given.
func (s StoreConfig) DisplayTitle() string {
	if s.Title == "" {
		return s.ID
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
