// The browser door.
//
// Authorization code flow with PKCE against any OIDC issuer. keyway assumes
// nothing about how an issuer spells things (ADR-0003): the claim carrying
// groups is named in config, and group names are matched exactly — an issuer
// that wants a grant to a parent group to cover the teams inside it emits the
// ancestors in the claim.

package infra

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kotsmile/keyway/config"
	"github.com/kotsmile/keyway/internal/identity/entity"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
)

// Oidc is a configured issuer, discovered once at boot.
//
// It implements identityservice.Issuer, which is what the transport holds:
// Pending and SignedIn are the identity domain's vocabulary, and everything
// about discovery documents, PKCE verifiers and claim paths stops here.
type Oidc struct {
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	http        *http.Client
	groupsClaim string
	rolesClaim  string
	rolePrefix  string
}

var _ identityservice.Issuer = (*Oidc)(nil)

// Discover discovers the issuer.
//
// At boot rather than per request: a console that only discovers its issuer
// when somebody tries to sign in is one that looks healthy while being
// unusable.
func Discover(ctx context.Context, cfg config.Oidc) (*Oidc, error) {
	client := &http.Client{
		// An issuer that redirects is an issuer being impersonated.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering %s: %w", cfg.Issuer, err)
	}

	return &Oidc{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		http:        client,
		groupsClaim: cfg.GroupsClaim,
		rolesClaim:  cfg.RolesClaim,
		rolePrefix:  cfg.RolePrefix,
	}, nil
}

// Start is where to send somebody, and what to remember while they are gone.
func (o *Oidc) Start() identityservice.Pending {
	verifier := oauth2.GenerateVerifier()
	csrf := randomToken()
	nonce := randomToken()
	return identityservice.Pending{
		AuthorizeURL: o.oauth.AuthCodeURL(csrf,
			oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)),
		CSRF:         csrf,
		Nonce:        nonce,
		PKCEVerifier: verifier,
	}
}

// Finish exchanges the code for an identity.
//
// It errors when the exchange fails, the id token is absent or its claims do
// not verify.
func (o *Oidc) Finish(
	ctx context.Context, code, nonce, pkceVerifier string,
) (*identityservice.SignedIn, error) {
	ctx = oidc.ClientContext(ctx, o.http)
	tokens, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging the authorization code: %w", err)
	}

	raw, ok := tokens.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("the issuer returned no id token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verifying the id token: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("verifying the id token: the nonce did not match")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("reading the id token claims: %w", err)
	}

	// `preferred_username` is the handle everything keys and logs on; the
	// subject is stable but unreadable, and an audit log full of uuids
	// answers nobody's question.
	username, _ := claims["preferred_username"].(string)
	handle, handleErr := entity.NewHandle(username)
	if handleErr != nil {
		// A claim with no usable username at all. The subject is always
		// present and always non-empty, so this is the fallback that cannot
		// itself fail.
		handle, handleErr = entity.NewHandle(idToken.Subject)
		if handleErr != nil {
			return nil, fmt.Errorf("reading the id token claims: the issuer named nobody")
		}
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	// Only prefixed words are candidates: a realm namespaces its keyway roles
	// (`keyway:admin`) precisely so its other systems' roles are not read as
	// keyway's. What survives the prefix is then a role word like any other,
	// and unknown ones are dropped and named — the same accept-and-warn the
	// dev_roles list gets, from the same function.
	var prefixed []string
	for _, word := range stringsAt(claims, o.rolesClaim) {
		if stripped, ok := strings.CutPrefix(word, o.rolePrefix); ok {
			prefixed = append(prefixed, stripped)
		}
	}
	roles, unknown := entity.ParseRoles(prefixed)
	if len(unknown) > 0 {
		slog.Warn("the roles claim carries keyway-prefixed roles this build does not have",
			"user", handle.String(), "unknown", unknown, "known", entity.RoleWords())
	}

	groups, dropped := entity.GroupNamesOf(stringsAt(claims, o.groupsClaim))
	if len(dropped) > 0 {
		slog.Warn("the groups claim carries entries that name no group; they are ignored",
			"user", handle.String(), "dropped", len(dropped))
	}

	return &identityservice.SignedIn{
		Handle: handle,
		Email:  email,
		Name:   name,
		Groups: groups,
		Roles:  roles,
	}, nil
}

// stringsAt reads a claim by dotted path, e.g. `realm_access.roles`.
//
// A path rather than a key because issuers nest: Keycloak puts realm roles
// under `realm_access.roles`, and a flat lookup would find nothing and grant
// nothing, silently.
func stringsAt(claims map[string]any, path string) []string {
	var current any = claims
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[segment]
		if !ok {
			return nil
		}
	}
	switch value := current.(type) {
	case []any:
		words := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				words = append(words, s)
			}
		}
		return words
	case string:
		// A single string is a claim with one value, which some issuers emit
		// rather than a one-element array.
		return []string{value}
	}
	return nil
}

// randomToken is 32 bytes of entropy, url-safe. Used for the csrf state and
// the nonce; crypto/rand never fails on a platform this runs on.
func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // Documented to never happen since Go 1.24.
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
