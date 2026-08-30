// The inventory over HTTP.
//
// Secrets are addressed by uuid throughout. Resolving one to a (store, name)
// is this layer's job, and it is deliberately a scan of what the caller can
// already see — a lookup table would be a second source of truth about where
// a secret lives.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kotsmile/keyway/config"
	accessentity "github.com/kotsmile/keyway/internal/access/entity"
	auditentity "github.com/kotsmile/keyway/internal/audit/entity"
	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
)

// mountSecrets registers the inventory's routes on the authenticated API router.
func mountSecrets(api chi.Router, state *State) {
	api.Get("/stores", Handler(listStores(state)))
	api.Get("/secrets", Handler(listSecrets(state)))
	api.Post("/secrets", Handler(create(state)))
	api.Get("/secrets/{id}", Handler(view(state)))
	api.Delete("/secrets/{id}", Handler(deleteSecret(state)))
	api.Get("/secrets/{id}/value", Handler(reveal(state)))
	api.Get("/secrets/{id}/versions", Handler(versions(state)))
	api.Post("/secrets/{id}/versions", Handler(patch(state)))
	api.Get("/secrets/{id}/history", Handler(history(state)))
}

// SecretView is a secret as the API reports it: addressed by uuid, and
// carrying how far this caller gets.
type SecretView struct {
	ID            uuid.UUID              `json:"id"`
	Store         string                 `json:"store"`
	Name          string                 `json:"name"`
	Labels        secretsentity.Metadata `json:"labels,omitempty"`
	LatestVersion string                 `json:"latest_version,omitempty"`
	Level         *accessentity.Level    `json:"level"`
	// Basis is why this caller can see it — an owner needs to know they are
	// one.
	Basis string `json:"basis"`
}

func secretViewOf(secret secretsentity.Secret, access accessentity.Access) SecretView {
	return SecretView{
		ID:            secretsentity.IDFor(secret),
		Store:         secret.Store,
		Name:          secret.Name,
		Labels:        secret.Labels,
		LatestVersion: secret.LatestVersion,
		Level:         access.Level,
		Basis:         basisWire(access.Basis),
	}
}

// basisWire spells a basis the way the Rust server did: the Debug rendering,
// lowercased. For a delegated grant that was `delegated { subject: "sre" }`,
// subject and all — the clients compare only "owner" and "admin" exactly and
// print the rest, so the odd-looking string is the compatible one.
//
// strconv.Quote rather than json.Marshal: Marshal HTML-escapes `<`, `>` and
// `&` into < and friends, which Rust's {:?} never did. Quote matches the
// Debug escaping for printable text — quotes and backslashes escaped,
// everything else verbatim.
func basisWire(basis accessentity.Basis) string {
	if subject, ok := basis.DelegatedTo(); ok {
		return strings.ToLower("delegated { subject: " + strconv.Quote(subject) + " }")
	}
	return basis.String()
}

// StoreView is one mounted Store, as the console's menu shows it.
type StoreView struct {
	ID    string        `json:"id"`
	Title string        `json:"title"`
	Allow []config.Verb `json:"allow"`
}

func listStores(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		stores := state.Stores.All()
		out := make([]StoreView, 0, len(stores))
		for _, store := range stores {
			out = append(out, StoreView{
				ID:    store.ID(),
				Title: store.Config().DisplayTitle(),
				Allow: store.Config().Allow,
			})
		}
		WriteJSON(w, out)
		return nil
	}
}

// listSecrets is every secret this caller can see, across every Store.
//
// A Store that fails is reported as empty rather than failing the whole
// listing: one unreachable cloud project must not black out the console.
func listSecrets(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := Caller(ctx)
		now := state.Now()

		out := make([]SecretView, 0)
		for _, store := range state.Stores.All() {
			listed, err := store.List(ctx)
			if err != nil {
				slog.Warn("listing failed", "store", store.ID(), "error", err)
				continue
			}
			for _, secret := range listed {
				access, err := state.Access.AccessFor(ctx, actor, secret.Store, secret.Name, now)
				if err != nil {
					return Internal(err)
				}
				if access.IsVisible() {
					out = append(out, secretViewOf(secret, access))
				}
			}
		}
		WriteJSON(w, out)
		return nil
	}
}

// secretID reads the uuid a route addresses. The Rust Path<Uuid> extractor
// answered 400 for anything else — a name is not an address.
func secretID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, BadRequest("the id must be a uuid")
	}
	return id, nil
}

// resolve finds the secret a uuid names, and how far this caller gets on it.
//
// Returns not-found both for a secret that does not exist and for one this
// caller may not see: a distinguishable answer would let anyone enumerate the
// inventory.
func resolve(
	r *http.Request, state *State, actor identityentity.Actor, id uuid.UUID,
) (*secretsservice.Store, secretsentity.Secret, accessentity.Access, error) {
	ctx := r.Context()
	now := state.Now()
	for _, store := range state.Stores.All() {
		listed, err := store.List(ctx)
		if err != nil {
			continue
		}
		for _, secret := range listed {
			if secretsentity.IDFor(secret) != id {
				continue
			}
			access, err := state.Access.AccessFor(ctx, actor, secret.Store, secret.Name, now)
			if err != nil {
				return nil, secretsentity.Secret{}, accessentity.Access{}, Internal(err)
			}
			if !access.IsVisible() {
				return nil, secretsentity.Secret{}, accessentity.Access{}, NotFound()
			}
			return store, secret, access, nil
		}
	}
	return nil, secretsentity.Secret{}, accessentity.Access{}, NotFound()
}

func view(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := secretID(r)
		if err != nil {
			return err
		}
		_, secret, access, err := resolve(r, state, Caller(r.Context()), id)
		if err != nil {
			return err
		}
		WriteJSON(w, secretViewOf(secret, access))
		return nil
	}
}

// reveal reads a value. Always audited — the reason `reveal` is a word
// separate from "read".
func reveal(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := Caller(ctx)
		id, err := secretID(r)
		if err != nil {
			return err
		}
		query := r.URL.Query()
		// `?key=` present-but-empty still narrows, the way Some("") did.
		key, hasKey := query.Get("key"), query.Has("key")
		version := query.Get("version")

		store, secret, access, err := resolve(r, state, actor, id)
		if err != nil {
			return err
		}

		permitted := access.Allows(accessentity.Read)
		if hasKey {
			permitted = access.AllowsKey(accessentity.Read, key)
		}
		if !permitted {
			return Forbidden()
		}

		payload, err := store.Access(ctx, secret.Name, version)
		if err != nil {
			return err
		}

		recordedVersion := version
		if recordedVersion == "" {
			recordedVersion = secret.LatestVersion
		}
		record := auditentity.NewRecord(auditentity.Reveal, id, secret.Store, secret.Name).
			WithVersion(recordedVersion)
		if hasKey {
			record = record.WithKeys([]string{key})
		}
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return Internal(err)
		}

		body, err := valueFor(payload, key, hasKey)
		if err != nil {
			return err
		}
		// Nothing on the way back should keep this.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(body))
		return nil
	}
}

// valueFor is one key of a kv payload, or the payload verbatim.
//
// A kv secret is JSON by the time it reaches here, which is what lets a
// backend with native key/value serve one natively and one without not be
// asked to fake it.
func valueFor(payload []byte, key string, hasKey bool) (string, error) {
	if !hasKey {
		return string(payload), nil
	}
	var parsed any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return "", BadRequest("this secret has no keys")
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		// Valid JSON with no keys to index — the Rust `.get` answered None,
		// which reported as not found.
		return "", NotFound()
	}
	value, ok := object[key]
	if !ok {
		return "", NotFound()
	}
	// A string comes back raw, not JSON-quoted: a quoted value would land in
	// a Kubernetes Secret with the quotes in it. Anything else re-renders as
	// compact JSON, the way serde_json's to_string did.
	if s, ok := value.(string); ok {
		return s, nil
	}
	rendered, err := json.Marshal(value)
	if err != nil {
		return "", Internal(err)
	}
	return string(rendered), nil
}

type createBody struct {
	Store *string `json:"store"`
	Name  *string `json:"name"`
	Value *string `json:"value"`
	Note  string  `json:"note"`
}

// create brings a new secret into the inventory, owned by whoever made it.
func create(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := Caller(ctx)
		var body createBody
		if err := DecodeJSON(r, &body); err != nil {
			return err
		}
		switch {
		case body.Store == nil:
			return MissingField("store")
		case body.Name == nil:
			return MissingField("name")
		case body.Value == nil:
			return MissingField("value")
		}

		if !actor.MayCreate() {
			return Forbidden()
		}
		store := state.Stores.Get(*body.Store)
		if store == nil {
			return NotFound()
		}

		labels := secretsentity.Metadata{
			secretsentity.IDLabel: secretsentity.Derive(*body.Store, *body.Name).String(),
		}
		if err := store.Create(ctx, *body.Name, labels); err != nil {
			return err
		}
		version, err := store.AddVersion(ctx, *body.Name, []byte(*body.Value))
		if err != nil {
			return err
		}

		// Ownership before audit: a secret with no owner is one nobody is
		// answerable for, and the window should be as short as possible.
		if err := state.Access.SetOwner(ctx, accessentity.Ownership{
			Store:  *body.Store,
			Secret: *body.Name,
			Owner:  actor.Handle(),
			Since:  state.Now(),
		}); err != nil {
			return Internal(err)
		}

		// A fresh secret's uuid is the derived one — creation stamped it as
		// the keyway-id label just above.
		record := auditentity.NewRecord(
			auditentity.Create, secretsentity.Derive(*body.Store, *body.Name), *body.Store, *body.Name,
		).WithVersion(version.ID).WithNote(body.Note)
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return Internal(err)
		}

		secret, err := store.Get(ctx, *body.Name)
		if err != nil {
			return err
		}
		access, err := state.Access.AccessFor(ctx, actor, *body.Store, *body.Name, state.Now())
		if err != nil {
			return Internal(err)
		}
		WriteJSON(w, secretViewOf(secret, access))
		return nil
	}
}

type patchBody struct {
	Value *string `json:"value"`
	Note  string  `json:"note"`
}

// patch writes a new version.
func patch(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := Caller(ctx)
		id, err := secretID(r)
		if err != nil {
			return err
		}
		var body patchBody
		if err := DecodeJSON(r, &body); err != nil {
			return err
		}
		if body.Value == nil {
			return MissingField("value")
		}

		store, secret, access, err := resolve(r, state, actor, id)
		if err != nil {
			return err
		}
		if !access.Allows(accessentity.Write) {
			return Forbidden()
		}

		version, err := store.AddVersion(ctx, secret.Name, []byte(*body.Value))
		if err != nil {
			return err
		}

		record := auditentity.NewRecord(auditentity.Update, id, secret.Store, secret.Name).
			WithVersion(version.ID).WithNote(body.Note)
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return Internal(err)
		}

		WriteJSON(w, version)
		return nil
	}
}

func versions(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := secretID(r)
		if err != nil {
			return err
		}
		store, secret, _, err := resolve(r, state, Caller(r.Context()), id)
		if err != nil {
			return err
		}
		listed, err := store.Versions(r.Context(), secret.Name)
		if err != nil {
			return err
		}
		WriteJSON(w, listed)
		return nil
	}
}

func history(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := secretID(r)
		if err != nil {
			return err
		}
		_, secret, _, err := resolve(r, state, Caller(r.Context()), id)
		if err != nil {
			return err
		}
		entries, err := state.Audit.ForSecret(r.Context(), secret.Store, secret.Name, 200)
		if err != nil {
			return Internal(err)
		}
		WriteJSON(w, entries)
		return nil
	}
}

// deleteSecret destroys a secret. Only its owner or an admin, and never from
// the CLI (ADR-0005).
func deleteSecret(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := Caller(ctx)
		id, err := secretID(r)
		if err != nil {
			return err
		}
		store, secret, access, err := resolve(r, state, actor, id)
		if err != nil {
			return err
		}
		// Deliberately narrower than `write`: a delegation at write may push
		// a new version, and that is not the same power as losing the secret
		// entirely.
		if access.Basis != accessentity.BasisOwner && access.Basis != accessentity.BasisAdmin {
			return Forbidden()
		}

		if err := store.Delete(ctx, secret.Name); err != nil {
			return err
		}
		record := auditentity.NewRecord(auditentity.Delete, id, secret.Store, secret.Name)
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return Internal(err)
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
