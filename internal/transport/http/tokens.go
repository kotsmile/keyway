// The tokens page.
//
// Every route here is scoped to the CALLER's own subject, and there is no
// admin view. That is a deliberate asymmetry with the rest of keyway: an
// admin sees every secret because secrets are the thing being administered,
// whereas a list of somebody else's credentials is a target — and seeing it
// would not let an admin do anything they cannot already do by revoking.
package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	tokensentity "github.com/kotsmile/keyway/internal/tokens/entity"
)

// mountTokens registers the token routes on the authenticated API router.
func mountTokens(api chi.Router, state *State) {
	api.Get("/tokens", Handler(listTokens(state)))
	api.Post("/tokens", Handler(mint(state)))
	api.Delete("/tokens/{id}", Handler(revokeToken(state)))
}

func listTokens(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := Caller(r.Context())
		tokens, err := state.Tokens.List(r.Context(), actor.Handle())
		if err != nil {
			return Internal(err)
		}
		WriteJSON(w, tokens)
		return nil
	}
}

type mintBody struct {
	Name *string `json:"name"`
	// Days bounds the token; 0 or absent means it does not expire.
	//
	// Days rather than a timestamp because it is a choice being made now, not
	// a date being transcribed — and a client computing the instant is a
	// client that can compute it in the wrong timezone.
	Days int64 `json:"days"`
}

// mintedView carries the one and only time the plaintext exists anywhere.
//
// The token field is the plain string, not the Plaintext type: this is the
// one place a token is meant to be written out, and the type's whole job is
// to redact everywhere else.
type mintedView struct {
	ID        tokensentity.ID   `json:"id"`
	Name      tokensentity.Name `json:"name"`
	Token     string            `json:"token"`
	ExpiresAt *time.Time        `json:"expires_at"`
}

func mint(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := Caller(r.Context())
		var body mintBody
		if err := DecodeJSON(r, &body); err != nil {
			return err
		}
		if body.Name == nil {
			return MissingField("name")
		}
		if body.Days < 0 {
			return BadRequest("days cannot be negative")
		}
		// Read at the edge, and reported in the entity's own words — the same
		// sentence and the same 400 the service answered with when it did
		// this check itself.
		name, err := tokensentity.NewName(*body.Name)
		if err != nil {
			return BadRequest(err.Error())
		}
		var expiresAt *time.Time
		if body.Days > 0 {
			expires := state.Now().Add(time.Duration(body.Days) * 24 * time.Hour)
			expiresAt = &expires
		}

		minted, err := state.Tokens.Mint(r.Context(), actor.Handle(), name, expiresAt)
		if err != nil {
			return BadRequest(err.Error())
		}

		slog.Info("token issued",
			"token_id", minted.Token.ID.String(), "user", actor.Handle(), "name", minted.Token.Name.String())

		// no-store on the one response that carries a credential, for the
		// same reason a reveal sets it: nothing on the way back should keep
		// this.
		w.Header().Set("Cache-Control", "no-store")
		WriteJSONStatus(w, http.StatusCreated, mintedView{
			ID:        minted.Token.ID,
			Name:      minted.Token.Name,
			Token:     minted.Plaintext.Expose(),
			ExpiresAt: minted.Token.ExpiresAt,
		})
		return nil
	}
}

func revokeToken(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := Caller(r.Context())
		// An id this build could never have minted is reported as no such
		// token, which is what the delete already answered for one that
		// simply is not there — and for the same reason: a different answer
		// would confirm which ids are real.
		id, err := tokensentity.ParseID(chi.URLParam(r, "id"))
		if err != nil {
			return NotFound()
		}
		gone, err := state.Tokens.Revoke(r.Context(), actor.Handle(), id)
		if err != nil {
			return Internal(err)
		}
		if !gone {
			// 404 for somebody else's token as well as for one that never
			// existed: a 403 would confirm that the id names a real token,
			// which is a fact nobody has any business learning by guessing.
			return NotFound()
		}
		slog.Info("token revoked", "token_id", id.String(), "user", actor.Handle())
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
