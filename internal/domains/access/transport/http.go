// Package transport is grants over HTTP.
//
// Delegating is scriptable and destroying is not (ADR-0005): a mistaken grant
// is visible in the audit log and revocable in a click, whereas a deleted
// secret has no undo.
package transport

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kotsmile/keyway/internal/domains/access/entity"
	auditentity "github.com/kotsmile/keyway/internal/domains/audit/entity"
	identityentity "github.com/kotsmile/keyway/internal/domains/identity/entity"
	secretsentity "github.com/kotsmile/keyway/internal/domains/secrets/entity"
	"github.com/kotsmile/keyway/internal/transport"
)

// Mount registers the grant routes on the authenticated API router.
func Mount(api chi.Router, state *transport.State) {
	api.Get("/secrets/{id}/grants", transport.Handler(list(state)))
	api.Post("/secrets/{id}/grants", transport.Handler(delegate(state)))
	api.Delete("/secrets/{id}/grants/{grant}", transport.Handler(revoke(state)))
}

// GrantView is a delegation as the API reports it.
type GrantView struct {
	ID          uuid.UUID    `json:"id"`
	SubjectKind string       `json:"subject_kind"`
	Subject     string       `json:"subject"`
	Level       entity.Level `json:"level"`
	Keys        []string     `json:"keys,omitempty"`
	GrantedBy   string       `json:"granted_by"`
	GrantedAt   time.Time    `json:"granted_at"`
	ExpiresAt   *time.Time   `json:"expires_at"`
	Note        string       `json:"note,omitempty"`
}

func viewOf(grant entity.Delegation) GrantView {
	return GrantView{
		ID:          grant.ID,
		SubjectKind: grant.Subject.Kind(),
		Subject:     grant.Subject.ID(),
		Level:       grant.Level,
		Keys:        grant.Keys,
		GrantedBy:   grant.GrantedBy,
		GrantedAt:   grant.GrantedAt,
		ExpiresAt:   grant.ExpiresAt,
		Note:        grant.Note,
	}
}

// list is who can see this secret — the list the whole mechanism exists to
// make readable.
func list(state *transport.State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := secretID(r, "id")
		if err != nil {
			return err
		}
		store, secret, err := locate(r, state, transport.Caller(r.Context()), id)
		if err != nil {
			return err
		}
		grants, err := state.Access.GrantsOn(r.Context(), store, secret)
		if err != nil {
			return transport.Internal(err)
		}
		out := make([]GrantView, 0, len(grants))
		for _, grant := range grants {
			out = append(out, viewOf(grant))
		}
		transport.WriteJSON(w, out)
		return nil
	}
}

type delegateBody struct {
	// SubjectKind is `user` or `group`, always explicit — a team called `sre`
	// and a person called `sre` are different subjects (ADR-0003).
	SubjectKind *string  `json:"subject_kind"`
	Subject     *string  `json:"subject"`
	Level       *string  `json:"level"`
	Keys        []string `json:"keys"`
	Days        int64    `json:"days"`
	Note        string   `json:"note"`
}

func delegate(state *transport.State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := transport.Caller(ctx)
		id, err := secretID(r, "id")
		if err != nil {
			return err
		}
		var body delegateBody
		if err := transport.DecodeJSON(r, &body); err != nil {
			return err
		}
		switch {
		case body.SubjectKind == nil:
			return transport.MissingField("subject_kind")
		case body.Subject == nil:
			return transport.MissingField("subject")
		case body.Level == nil:
			return transport.MissingField("level")
		}

		store, secret, err := locate(r, state, actor, id)
		if err != nil {
			return err
		}

		// Only an owner or an admin hands out sight of a secret. A delegation
		// at `write` does not carry the right to re-delegate: that belongs to
		// ownership, which is a different act with a different audit line.
		access, err := state.Access.AccessFor(ctx, actor, store, secret, state.Now())
		if err != nil {
			return transport.Internal(err)
		}
		if access.Basis != entity.BasisOwner && access.Basis != entity.BasisAdmin {
			return transport.Forbidden()
		}

		var subject entity.Subject
		switch *body.SubjectKind {
		case "user":
			subject = entity.User(*body.Subject)
		case "group":
			subject = entity.Group(*body.Subject)
		default:
			return transport.BadRequest(fmt.Sprintf(
				"subject_kind must be user or group, not %q", *body.SubjectKind))
		}
		level, err := entity.ParseLevel(*body.Level)
		if err != nil {
			return transport.BadRequest(err.Error())
		}

		now := state.Now()
		grant := entity.Delegation{
			ID:        uuid.New(),
			Store:     store,
			Secret:    secret,
			Subject:   subject,
			Level:     level,
			Keys:      body.Keys,
			GrantedBy: actor.Handle(),
			GrantedAt: now,
			Note:      body.Note,
		}
		if body.Days > 0 {
			expires := now.Add(time.Duration(body.Days) * 24 * time.Hour)
			grant.ExpiresAt = &expires
		}

		if err := state.Access.Delegate(ctx, grant); err != nil {
			return transport.Internal(err)
		}

		record := auditentity.NewRecord(auditentity.Delegate, id, store, secret).
			WithSubject(*body.Subject).WithKeys(grant.Keys).WithNote(grant.Note)
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return transport.Internal(err)
		}

		transport.WriteJSON(w, viewOf(grant))
		return nil
	}
}

func revoke(state *transport.State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		actor := transport.Caller(ctx)
		id, err := secretID(r, "id")
		if err != nil {
			return err
		}
		grantID, err := secretID(r, "grant")
		if err != nil {
			return err
		}

		store, secret, err := locate(r, state, actor, id)
		if err != nil {
			return err
		}

		access, err := state.Access.AccessFor(ctx, actor, store, secret, state.Now())
		if err != nil {
			return transport.Internal(err)
		}
		if access.Basis != entity.BasisOwner && access.Basis != entity.BasisAdmin {
			return transport.Forbidden()
		}

		grants, err := state.Access.GrantsOn(ctx, store, secret)
		if err != nil {
			return transport.Internal(err)
		}
		subject := ""
		found := false
		for _, grant := range grants {
			if grant.ID == grantID {
				subject = grant.Subject.ID()
				found = true
				break
			}
		}
		if !found {
			return transport.NotFound()
		}

		removed, err := state.Access.Revoke(ctx, grantID)
		if err != nil {
			return transport.Internal(err)
		}
		if !removed {
			return transport.NotFound()
		}

		record := auditentity.NewRecord(auditentity.Revoke, id, store, secret).
			WithSubject(subject)
		if err := state.Audit.Record(ctx, actor, record); err != nil {
			return transport.Internal(err)
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// secretID reads one uuid path parameter; anything else is 400, the way the
// Rust Path<Uuid> extractor answered.
func secretID(r *http.Request, param string) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, param))
	if err != nil {
		return uuid.Nil, transport.BadRequest("the id must be a uuid")
	}
	return id, nil
}

// locate is which secret a uuid names, for a caller who can already see it.
//
// The same scan the secrets transport does, duplicated the way the Rust
// domains each carried their own — a shared resolver would couple the two
// domains over three lines of loop.
func locate(
	r *http.Request, state *transport.State, actor identityentity.Actor, id uuid.UUID,
) (string, string, error) {
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
				return "", "", transport.Internal(err)
			}
			if !access.IsVisible() {
				return "", "", transport.NotFound()
			}
			return secret.Store, secret.Name, nil
		}
	}
	return "", "", transport.NotFound()
}
