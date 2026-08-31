// Signing in and out.
package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
)

// pendingCookie is where the details of a redirect in progress are kept while
// the caller is at the issuer.
//
// In a cookie rather than server memory, so a sign-in survives hitting a
// different replica than the one that started it.
const pendingCookie = "keyway_pending"

// mountIdentity registers the sign-in routes on the root router. Sign-in lives at the
// root, not under /api: a browser is redirected here, and /api is for things
// that speak JSON.
func mountIdentity(root chi.Router, state *State) {
	root.Get("/auth/login", Handler(login(state)))
	root.Get("/auth/callback", Handler(callback(state)))
	root.Get("/auth/logout", logout)
}

// mountIdentityAPI registers who-am-I on the authenticated API router.
func mountIdentityAPI(api chi.Router, state *State) {
	api.Get("/me", Handler(me(state)))
}

// pending mirrors the Rust Pending cookie payload.
type pending struct {
	CSRF         string `json:"csrf"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkce_verifier"`
}

// login sends somebody to their identity provider.
func login(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if state.Oidc == nil {
			return BadRequest("this deployment has no issuer configured")
		}

		started := state.Oidc.Start()
		payload, err := json.Marshal(pending{
			CSRF:         started.CSRF,
			Nonce:        started.Nonce,
			PKCEVerifier: started.PKCEVerifier,
		})
		if err != nil {
			return Internal(err)
		}
		http.SetCookie(w, SealedCookie(state.Codec, pendingCookie, payload, 10*time.Minute))
		http.Redirect(w, r, started.AuthorizeURL, http.StatusSeeOther)
		return nil
	}
}

// callback is where the issuer sends them back.
func callback(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if state.Oidc == nil {
			return BadRequest("no issuer configured")
		}
		query := r.URL.Query()

		if issuerError := query.Get("error"); issuerError != "" {
			// The issuer refused. Its wording is the useful part.
			return BadRequest(fmt.Sprintf("sign-in refused: %s", issuerError))
		}

		var p pending
		opened := false
		if cookie, err := r.Cookie(pendingCookie); err == nil {
			if payload, ok := state.Codec.Open(pendingCookie, cookie.Value); ok {
				opened = json.Unmarshal(payload, &p) == nil
			}
		}
		if !opened {
			return BadRequest("this sign-in expired; start again")
		}

		// Without this a third party could hand somebody a callback url and
		// sign them in as an account of the attacker's choosing.
		if query.Get("state") != p.CSRF {
			return BadRequest("state did not match")
		}
		code := query.Get("code")
		if code == "" {
			return BadRequest("no code returned")
		}

		signedIn, err := state.Oidc.Finish(r.Context(), code, p.Nonce, p.PKCEVerifier)
		if err != nil {
			return Internal(err)
		}

		// Remembering the claim is what lets an API token act as this person
		// in full later on (ADR-0004).
		if err := state.Identity.SignIn(
			r.Context(), signedIn.Handle, signedIn.Groups,
			signedIn.Email, signedIn.Name, state.Now(),
		); err != nil {
			return Internal(err)
		}

		slog.Info("signed in", "user", signedIn.Handle.String(), "groups", len(signedIn.Groups))

		roles := make([]string, 0, len(signedIn.Roles))
		for _, role := range signedIn.Roles {
			roles = append(roles, role.String())
		}
		session := Session{
			Handle:    signedIn.Handle.String(),
			Groups:    identityentity.GroupWords(signedIn.Groups),
			Roles:     roles,
			ExpiresAt: state.Now().Add(time.Duration(state.SessionHours) * time.Hour),
		}
		cookie, err := session.Cookie(state.Codec, state.SessionHours)
		if err != nil {
			return Internal(err)
		}

		http.SetCookie(w, RemovalCookie(pendingCookie))
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}
}

// logout drops the session cookie.
//
// keyway holds no server-side session to invalidate, so this is the whole of
// signing out here. An API token is revoked separately — deleting the cookie
// does not touch one.
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, RemovalCookie(SessionCookie))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// meView is who the caller is, and what the console should look like.
type meView struct {
	Handle    string   `json:"handle"`
	Groups    []string `json:"groups"`
	Roles     []string `json:"roles"`
	IsAdmin   bool     `json:"is_admin"`
	MayCreate bool     `json:"may_create"`
	// Directory is whether one is configured. The console warns when
	// delegating to a group without one, because an API token cannot see such
	// a grant.
	Directory bool         `json:"directory"`
	Branding  brandingView `json:"branding"`
}

type brandingView struct {
	Name    string `json:"name"`
	Logo    string `json:"logo"`
	Favicon string `json:"favicon"`
	Accent  string `json:"accent"`
}

func me(state *State) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		actor := Caller(r.Context())
		WriteJSON(w, meView{
			Handle:    actor.Handle(),
			Groups:    actor.GroupNames(),
			Roles:     actor.RoleNames(),
			IsAdmin:   actor.IsAdmin(),
			MayCreate: actor.MayCreate(),
			Directory: state.Identity.HasDirectory(),
			Branding: brandingView{
				Name:    state.Branding.Name,
				Logo:    state.Branding.Logo,
				Favicon: state.Branding.Favicon,
				Accent:  state.Branding.Accent,
			},
		})
		return nil
	}
}
