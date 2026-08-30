// The audit feed.
package http

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// mountAudit registers the feed on the authenticated API router.
func mountAudit(api chi.Router, state *State) {
	api.Get("/audit", Handler(feed(state)))
}

// feed is everything, newest first — admin only.
//
// The one screen in keyway that shows what everybody else has been doing, so
// it is the one that needs a fence of its own. Paging is keyset (`before`)
// rather than an offset: the feed grows while somebody is reading it, and an
// offset would silently repeat or skip rows.
func feed(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := Caller(r.Context())
		if !actor.IsAdmin() {
			return Forbidden()
		}

		query := r.URL.Query()
		limit := int64(100)
		if raw := query.Get("limit"); raw != "" {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return BadRequest("limit must be an integer")
			}
			limit = parsed
		}
		var before *int64
		if raw := query.Get("before"); raw != "" {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return BadRequest("before must be an integer")
			}
			before = &parsed
		}

		limit = min(max(limit, 1), 500)
		entries, err := state.Audit.Feed(r.Context(), limit, before)
		if err != nil {
			return Internal(err)
		}
		WriteJSON(w, entries)
		return nil
	}
}
