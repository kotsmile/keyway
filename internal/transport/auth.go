// Turning a request into an Actor.
//
// Three doors, resolved in one place so no handler has to know which one a
// request came through:
//
//  1. an API token in `Authorization: Bearer kw-…`, acting as the person who
//     minted it (ADR-0004);
//  2. a browser session;
//  3. dev mode — with no issuer configured, keyway acts as the configured
//     user. Every authorisation decision is still made, so a local run
//     behaves like production minus the redirect.

package transport

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kotsmile/keyway/internal/domains/identity"
	identityentity "github.com/kotsmile/keyway/internal/domains/identity/entity"
	"github.com/kotsmile/keyway/internal/domains/tokens"
	tokensentity "github.com/kotsmile/keyway/internal/domains/tokens/entity"
)

// Auth is what resolving a caller needs.
type Auth struct {
	Tokens   *tokens.Service
	Identity *identity.Service
	// Dev is who a local run acts as. Nil once an issuer is configured.
	Dev *DevActor
	// Codec reads the session cookie.
	Codec *Codec
	// Now is injectable so a test can hold the clock still.
	Now func() time.Time
}

// DevActor is the identity a dev-mode run assumes.
type DevActor struct {
	Handle string
	Roles  []identityentity.Role
	Groups []string
}

// callerKey carries the resolved Actor through the request context.
type callerKey struct{}

// Caller is who is asking, resolved once per request by Middleware.
//
// A handler takes this rather than reading headers, so "which door was this"
// is answered in exactly one place. Calling it under any route Middleware did
// not wrap is a programming error worth crashing over.
func Caller(ctx context.Context) identityentity.Actor {
	actor, ok := ctx.Value(callerKey{}).(identityentity.Actor)
	if !ok {
		panic("transport.Caller outside the auth middleware")
	}
	return actor
}

// WithCaller is the context a resolved actor rides in. Exported for the
// router and for tests that call a handler directly.
func WithCaller(ctx context.Context, actor identityentity.Actor) context.Context {
	return context.WithValue(ctx, callerKey{}, actor)
}

// Middleware resolves the caller or refuses the request.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := a.Resolve(r)
		if err != nil {
			WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), actor)))
	})
}

// Resolve is the three doors, in the order the Rust extractor tried them.
func (a *Auth) Resolve(r *http.Request) (identityentity.Actor, error) {
	if presented, ok := bearer(r); ok {
		return a.resolveToken(r.Context(), presented)
	}

	if cookie, err := r.Cookie(SessionCookie); err == nil {
		if session, ok := SessionFromCookie(a.Codec, cookie.Value); ok {
			if session.IsLive(a.now()) {
				return session.Actor(), nil
			}
			// Expired rather than absent. Saying so is what lets the console
			// send somebody back to sign in instead of showing an empty page.
			slog.Debug("session expired", "user", session.Handle)
			return identityentity.Actor{}, Unauthorized()
		}
	}

	// No credential. In dev mode that is the configured user; otherwise it is
	// nobody.
	if a.Dev != nil {
		return identityentity.NewActor(a.Dev.Handle, a.Dev.Groups, a.Dev.Roles), nil
	}
	return identityentity.Actor{}, Unauthorized()
}

func bearer(r *http.Request) (string, bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (a *Auth) resolveToken(ctx context.Context, presented string) (identityentity.Actor, error) {
	token, err := a.Tokens.Verify(ctx, presented, a.now())
	if err != nil {
		// Every rejection reports the same way. Which one it was goes to the
		// log, because "that id exists but the secret is wrong" is a fact
		// worth guessing for.
		var rejected tokensentity.Rejected
		if errors.As(err, &rejected) {
			slog.Info("token rejected", "reason", rejected.Error())
			return identityentity.Actor{}, Unauthorized()
		}
		return identityentity.Actor{}, Internal(err)
	}

	// Roles are not carried by the token: it acts as its holder. Without a
	// Directory a token's roles are empty, which is deliberate — a role opens
	// no secret anyway (ADR-0002), and the grants addressed to the holder are
	// what matter.
	actor, err := a.Identity.ActorForToken(ctx, token.Subject, nil, token.ID)
	if err != nil {
		return identityentity.Actor{}, Internal(err)
	}
	if actor == nil {
		// Only reachable with a Directory configured: the account is disabled
		// or gone, which is exactly the property a Directory buys back.
		slog.Info("token holder is no longer active", "subject", token.Subject)
		return identityentity.Actor{}, Unauthorized()
	}
	return *actor, nil
}

func (a *Auth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}
