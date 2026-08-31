// Package access is who may see what.
//
// The rules live in entity and touch nothing: entity.Resolve is the whole
// authorisation test, and it takes the grants it is given rather than
// fetching them. The service below is the thin part — it loads, asks, and
// writes.
package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kotsmile/keyway/internal/access/entity"
	secrets "github.com/kotsmile/keyway/internal/secrets/entity"
)

// Repo is everything this domain needs from storage.
//
// Note what is absent: any method taking a caller. Filtering grants by who is
// asking would put half the authorisation rule in SQL, where the next person
// to write a query is free to get it wrong — so the repository answers "what
// grants exist on this secret" and entity.Resolve answers the rest.
type Repo interface {
	GrantsOn(ctx context.Context, store secrets.StoreID, secret secrets.SecretName) ([]entity.Delegation, error)
	OwnerOf(ctx context.Context, store secrets.StoreID, secret secrets.SecretName) (*entity.Ownership, error)
	GrantsForSubjects(ctx context.Context, subjects []entity.Subject) ([]entity.Delegation, error)
	SaveGrant(ctx context.Context, grant entity.Delegation) error
	RemoveGrant(ctx context.Context, id uuid.UUID) (bool, error)
	SetOwner(ctx context.Context, ownership entity.Ownership) error
}

// Service loads, asks, and writes.
type Service struct {
	repo Repo
}

// NewService wires the service to its storage.
func NewService(repo Repo) *Service {
	return &Service{repo: repo}
}

// AccessFor is how far `actor` gets on one secret.
func (s *Service) AccessFor(
	ctx context.Context, actor entity.Caller,
	store secrets.StoreID, secret secrets.SecretName, now time.Time,
) (entity.Access, error) {
	owner, err := s.repo.OwnerOf(ctx, store, secret)
	if err != nil {
		return entity.Access{}, err
	}
	grants, err := s.repo.GrantsOn(ctx, store, secret)
	if err != nil {
		return entity.Access{}, err
	}
	return entity.Resolve(actor, owner, grants, now), nil
}

// GrantsOn is every grant on one secret — the list that answers "who can see
// this".
func (s *Service) GrantsOn(
	ctx context.Context, store secrets.StoreID, secret secrets.SecretName,
) ([]entity.Delegation, error) {
	return s.repo.GrantsOn(ctx, store, secret)
}

// OwnerOf is who owns a secret, if anybody does.
func (s *Service) OwnerOf(
	ctx context.Context, store secrets.StoreID, secret secrets.SecretName,
) (*entity.Ownership, error) {
	return s.repo.OwnerOf(ctx, store, secret)
}

// GrantsFor is every grant addressed to this caller, across every secret —
// what a listing is narrowed by.
func (s *Service) GrantsFor(ctx context.Context, actor entity.Caller) ([]entity.Delegation, error) {
	return s.repo.GrantsForSubjects(ctx, actor.Subjects())
}

// Delegate writes a grant.
func (s *Service) Delegate(ctx context.Context, grant entity.Delegation) error {
	return s.repo.SaveGrant(ctx, grant)
}

// Revoke removes one. Returns whether there was one to remove.
func (s *Service) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.repo.RemoveGrant(ctx, id)
}

// SetOwner records who owns a secret. Replaces rather than adds: a transfer
// changes who is answerable, it does not produce a second owner.
func (s *Service) SetOwner(ctx context.Context, ownership entity.Ownership) error {
	return s.repo.SetOwner(ctx, ownership)
}

// Allows is whether `actor` may do `wanted` to this secret.
func (s *Service) Allows(
	ctx context.Context, actor entity.Caller,
	store secrets.StoreID, secret secrets.SecretName,
	wanted entity.Level, now time.Time,
) (bool, error) {
	access, err := s.AccessFor(ctx, actor, store, secret, now)
	if err != nil {
		return false, err
	}
	return access.Allows(wanted), nil
}
