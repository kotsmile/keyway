// Package service answers who is asking, and what keyway remembers about them.
package service

import (
	"context"
	"time"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

// Repo is what this domain needs from storage: the groups claim as it stood
// at a person's last sign-in.
type Repo interface {
	Remember(ctx context.Context, user *entity.RememberedUser) error
	// Recall is what was remembered, or nil if they have never signed in.
	Recall(ctx context.Context, handle entity.Handle) (*entity.RememberedUser, error)
}

// Directory is a live connection to the identity provider.
//
// Optional by design (ADR-0004): configured, it replaces remembered groups
// with a live answer and adds an account-enabled check. Unconfigured, keyway
// calls no identity provider on any request.
//
// Note what this port does NOT include: caching. How long an answer may be
// trusted is a policy about how fast a revocation must bite, not a property
// of Keycloak's REST API — it lives in CachedDirectory, in this package, and
// an implementation of this interface is expected to ask its provider every
// single time it is called.
type Directory interface {
	// Resolve is what the directory says about somebody right now, or nil
	// when they are gone from it entirely.
	Resolve(ctx context.Context, handle entity.Handle) (*DirectoryAnswer, error)
}

// DirectoryAnswer is what a Directory says about somebody right now.
type DirectoryAnswer struct {
	Enabled bool
	Groups  []entity.GroupName
}

// Issuer is the browser door, as this domain needs it.
//
// The port is declared here rather than in the transport that calls it,
// because Pending and SignedIn are this domain's vocabulary: what a redirect
// must remember while somebody is at their provider, and who came back. The
// OIDC client that implements it lives in infra and is the only thing that
// knows what a discovery document or a PKCE verifier is.
type Issuer interface {
	// Start is where to send somebody, and what to remember while they are
	// gone.
	Start() Pending
	// Finish exchanges the code for an identity. It fails when the exchange
	// fails, the id token is absent, or its claims do not verify.
	Finish(ctx context.Context, code, nonce, pkceVerifier string) (*SignedIn, error)
}

// Pending is what a redirect to the issuer needs remembering across it.
type Pending struct {
	AuthorizeURL string
	CSRF         string
	Nonce        string
	PKCEVerifier string
}

// SignedIn is who signed in, as the claim describes them.
type SignedIn struct {
	Handle entity.Handle
	Email  string
	Name   string
	Groups []entity.GroupName
	Roles  []entity.Role
}

// Service is the identity domain's operations, wire-agnostic.
type Service struct {
	repo      Repo
	directory Directory
}

// NewService builds the service. A nil directory means none is configured,
// and a token's groups are what was remembered at its holder's last sign-in.
func NewService(repo Repo, directory Directory) *Service {
	return &Service{repo: repo, directory: directory}
}

// SignIn records a sign-in. The groups are REPLACED, never merged: somebody
// removed from a team must lose it here on their next sign-in.
func (s *Service) SignIn(
	ctx context.Context, handle entity.Handle, groups []entity.GroupName,
	email, name string, at time.Time,
) error {
	return s.repo.Remember(ctx, &entity.RememberedUser{
		Handle:    handle,
		Groups:    groups,
		Email:     email,
		Name:      name,
		LastLogin: at,
	})
}

// ActorForToken is the actor a token acts as, or nil for nobody.
//
// With a Directory configured the groups are live and a disabled account
// resolves to nothing — which is what buys back "disable the account and
// every token it issued dies". Without one, they are what was remembered at
// the last sign-in.
func (s *Service) ActorForToken(
	ctx context.Context, handle entity.Handle, roles []entity.Role, tokenID string,
) (*entity.Actor, error) {
	var groups []entity.GroupName
	if s.directory != nil {
		answer, err := s.directory.Resolve(ctx, handle)
		if err != nil {
			return nil, err
		}
		if answer == nil || !answer.Enabled {
			// Disabled, or gone from the directory entirely.
			return nil, nil
		}
		groups = answer.Groups
	} else {
		user, err := s.repo.Recall(ctx, handle)
		if err != nil {
			return nil, err
		}
		if user != nil {
			groups = user.Groups
		}
	}
	actor := entity.NewActor(handle, groups, roles).ViaToken(tokenID)
	return &actor, nil
}

// Recall is what was remembered, or nil if they have never signed in.
func (s *Service) Recall(ctx context.Context, handle entity.Handle) (*entity.RememberedUser, error) {
	return s.repo.Recall(ctx, handle)
}

// HasDirectory is whether a Directory is configured — what the console shows
// when delegating to a group, since without one an API token cannot see the
// grant.
func (s *Service) HasDirectory() bool {
	return s.directory != nil
}
