// Package audit is what was done, and who did it.
//
// Reads are recorded alongside writes, which is unusual and intended: for a
// secrets tool the interesting question is far more often "who looked at
// this" than "who changed it".
//
// Append-only. There is no update and no delete in this domain.
package audit

import (
	"context"

	"github.com/kotsmile/keyway/internal/domains/audit/entity"
)

// Actor is who is acting, as this domain needs to see them: the handle, and
// the token the request arrived on when it arrived on one. The identity
// domain's Actor satisfies it.
type Actor interface {
	Handle() string
	// TokenID is the public id of the API token this request arrived on, or
	// "" for a browser session.
	TokenID() string
}

// Repo is what this domain needs from storage.
type Repo interface {
	// Append writes one entry. viaToken "" is a browser session and is stored
	// as NULL, the way the Rust server stored an absent token.
	Append(ctx context.Context, actor, viaToken string, record entity.Record) error
	ForSecret(ctx context.Context, store, secret string, limit int64) ([]entity.Entry, error)
	Feed(ctx context.Context, limit int64, before *int64) ([]entity.Entry, error)
}

// Service appends and reads back.
type Service struct {
	repo Repo
}

// NewService wires the service to its storage.
func NewService(repo Repo) *Service {
	return &Service{repo: repo}
}

// Record appends one entry.
//
// The actor supplies both the handle and, when the request arrived on one,
// the token id — taken from the same place, so a caller cannot record a
// reveal as somebody else by passing the wrong string.
func (s *Service) Record(ctx context.Context, actor Actor, record entity.Record) error {
	return s.repo.Append(ctx, actor.Handle(), actor.TokenID(), record)
}

// ForSecret is what has been done to one secret, newest first.
func (s *Service) ForSecret(ctx context.Context, store, secret string, limit int64) ([]entity.Entry, error) {
	return s.repo.ForSecret(ctx, store, secret, limit)
}

// Feed is everything, newest first.
//
// Only an admin has any business calling this; the fence is the caller's,
// because a repository that decides who may read it is a repository with two
// jobs.
func (s *Service) Feed(ctx context.Context, limit int64, before *int64) ([]entity.Entry, error) {
	return s.repo.Feed(ctx, limit, before)
}
