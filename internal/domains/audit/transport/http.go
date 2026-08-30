// Package transport is the audit feed.
package transport

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/kotsmile/keyway/internal/transport"
)

// Mount registers the feed on the authenticated API router.
func Mount(api chi.Router, state *transport.State) {
	api.Get("/audit", transport.Handler(feed(state)))
}

// feed is everything, newest first — admin only.
//
// The one screen in keyway that shows what everybody else has been doing, so
// it is the one that needs a fence of its own. Paging is keyset (`before`)
// rather than an offset: the feed grows while somebody is reading it, and an
// offset would silently repeat or skip rows.
func feed(state *transport.State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := transport.Caller(r.Context())
		if !actor.IsAdmin() {
			return transport.Forbidden()
		}

		query := r.URL.Query()
		limit := int64(100)
		if raw := query.Get("limit"); raw != "" {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return transport.BadRequest("limit must be an integer")
			}
			limit = parsed
		}
		var before *int64
		if raw := query.Get("before"); raw != "" {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return transport.BadRequest("before must be an integer")
			}
			before = &parsed
		}

		limit = min(max(limit, 1), 500)
		entries, err := state.Audit.Feed(r.Context(), limit, before)
		if err != nil {
			return transport.Internal(err)
		}
		transport.WriteJSON(w, entries)
		return nil
	}
}
