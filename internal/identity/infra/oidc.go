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
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kotsmile/keyway/config"
	"github.com/kotsmile/keyway/internal/identity/entity"
)

// Oidc is a configured issuer, discovered once at boot.
type Oidc struct {
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	http        *http.Client
	groupsClaim string
	rolesClaim  string
	rolePrefix  string
}

// SignedIn is who signed in, as the claim describes them.
type SignedIn struct {
	Handle string
	Email  string
	Name   string
	Groups []string
	Roles  []entity.Role
}

// Pending is what a redirect to the issuer needs remembering across it.
type Pending struct {
	AuthorizeURL string
	CSRF         string
	Nonce        string
	PKCEVerifier string
}

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
func (o *Oidc) Start() Pending {
	verifier := oauth2.GenerateVerifier()
	csrf := randomToken()
	nonce := randomToken()
	return Pending{
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
func (o *Oidc) Finish(ctx context.Context, code, nonce, pkceVerifier string) (*SignedIn, error) {
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
	handle, _ := claims["preferred_username"].(string)
	if handle == "" {
		handle = idToken.Subject
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	var roles []entity.Role
	for _, word := range stringsAt(claims, o.rolesClaim) {
		stripped, prefixed := strings.CutPrefix(word, o.rolePrefix)
		if !prefixed {
			continue
		}
		if role, known := entity.ParseRole(stripped); known {
			roles = append(roles, role)
		}
	}

	return &SignedIn{
		Handle: handle,
		Email:  email,
		Name:   name,
		Groups: stringsAt(claims, o.groupsClaim),
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
