// Package tokens is the credential for callers that can hold no browser
// session.
//
// External Secrets, CI, the CLI. A token acts as the person who minted it and
// carries no grants of its own (ADR-0004).
package service

import (
	"context"
	"time"

	"github.com/kotsmile/keyway/internal/tokens/entity"
)

// Repo is what this domain needs from storage.
type Repo interface {
	Insert(ctx context.Context, token entity.StoredToken) (time.Time, error)
	ByID(ctx context.Context, id string) (*entity.StoredToken, error)
	ForSubject(ctx context.Context, subject string) ([]entity.Token, error)
	Delete(ctx context.Context, subject, id string) (bool, error)
	// Touch is best-effort: "last used" helps a person decide whether a token
	// is still needed and is never an authorisation input, so a failure to
	// write it must not fail a request.
	Touch(ctx context.Context, id string, at time.Time)
}

// Service mints, verifies, lists and revokes.
type Service struct {
	repo Repo
}

// NewService wires the service to its storage.
func NewService(repo Repo) *Service {
	return &Service{repo: repo}
}

// Mint mints a token for `subject`. The plaintext is returned once and never
// again — only its hash is stored.
func (s *Service) Mint(ctx context.Context, subject, name string, expiresAt *time.Time) (entity.Minted, error) {
	stored, plaintext, err := entity.Mint(subject, name, expiresAt)
	if err != nil {
		return entity.Minted{}, err
	}
	createdAt, err := s.repo.Insert(ctx, stored)
	if err != nil {
		return entity.Minted{}, err
	}
	return entity.Minted{
		Token: entity.Token{
			ID:        stored.ID,
			Subject:   stored.Subject,
			Name:      stored.Name,
			CreatedAt: createdAt,
			ExpiresAt: expiresAt,
			LastUsed:  nil,
		},
		Plaintext: plaintext,
	}, nil
}

// Verify resolves a presented token to the subject it acts as.
//
// A token that is simply not valid fails with an entity.Rejected, which is an
// answer rather than a failure: a caller logs which and reports all of them
// identically, telling one from a storage error with errors.Is. Anything else
// is storage being unreachable.
func (s *Service) Verify(ctx context.Context, presented string, now time.Time) (entity.Token, error) {
	id, secret, ok := entity.Split(presented)
	if !ok {
		return entity.Token{}, entity.Malformed
	}
	stored, err := s.repo.ByID(ctx, id)
	if err != nil {
		return entity.Token{}, err
	}
	if stored == nil {
		return entity.Token{}, entity.Unknown
	}
	if err := stored.Admits(secret, now); err != nil {
		return entity.Token{}, err
	}
	s.repo.Touch(ctx, id, now)
	return entity.Token{
		ID:        stored.ID,
		Subject:   stored.Subject,
		Name:      stored.Name,
		CreatedAt: stored.CreatedAt,
		ExpiresAt: stored.ExpiresAt,
		LastUsed:  stored.LastUsed,
	}, nil
}

// List is the tokens `subject` issued.
//
// There is deliberately no listing across subjects. An admin can see every
// secret because secrets are the thing being administered; a list of somebody
// else's credentials is a target, and seeing it would not let an admin do
// anything they cannot already do by disabling the account.
func (s *Service) List(ctx context.Context, subject string) ([]entity.Token, error) {
	return s.repo.ForSubject(ctx, subject)
}

// Revoke revokes one of `subject`'s tokens, returning whether there was one.
//
// A caller reports "no such token" both for somebody else's and for one that
// never existed: confirming that an id names a real token is a fact nobody
// has any business learning by guessing.
func (s *Service) Revoke(ctx context.Context, subject, id string) (bool, error) {
	return s.repo.Delete(ctx, subject, id)
}
