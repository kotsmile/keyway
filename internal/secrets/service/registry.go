package service

import "fmt"

// Registry is every configured Store, in declaration order.
//
// Declaration order is the order the console lists them in, so the config
// file decides what a person sees first.
type Registry struct {
	order []string
	byID  map[string]*Store
}

// DuplicateStoreError is two Stores answering to one id, which makes every
// grant written against it ambiguous — worth failing the process over rather
// than resolving arbitrarily.
type DuplicateStoreError struct {
	ID string
}

func (e *DuplicateStoreError) Error() string {
	return fmt.Sprintf("duplicate store id %q", e.ID)
}

// NewRegistry indexes the Stores.
//
// It fails when two Stores share an id.
func NewRegistry(stores []*Store) (*Registry, error) {
	order := make([]string, 0, len(stores))
	byID := make(map[string]*Store, len(stores))
	for _, store := range stores {
		id := store.ID()
		if _, taken := byID[id]; taken {
			return nil, &DuplicateStoreError{ID: id}
		}
		order = append(order, id)
		byID[id] = store
	}
	return &Registry{order: order, byID: byID}, nil
}

// Get resolves a Store id.
//
// It returns nil for an unknown one; the caller reports that the same way it
// reports an unknown secret, so a URL cannot be used to learn which Stores
// exist.
func (r *Registry) Get(id string) *Store {
	return r.byID[id]
}

// All is every Store, in declaration order.
func (r *Registry) All() []*Store {
	out := make([]*Store, 0, len(r.order))
	for _, id := range r.order {
		if store, ok := r.byID[id]; ok {
			out = append(out, store)
		}
	}
	return out
}

// IsEmpty is whether no Store is configured at all.
func (r *Registry) IsEmpty() bool { return len(r.order) == 0 }

// Len is how many Stores are mounted.
func (r *Registry) Len() int { return len(r.order) }
