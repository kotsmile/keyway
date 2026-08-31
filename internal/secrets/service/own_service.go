package service

import (
	"context"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// OwnStoreRepo is everything keyway's own Store needs from storage.
//
// It speaks in entities, not columns: the rules about which version is
// current, what a destroyed one yields and how the next number is chosen live
// in the entity package, and this interface only moves them.
type OwnStoreRepo interface {
	ListSecrets(ctx context.Context, store entity.StoreID) ([]entity.Secret, error)
	// GetSecret returns nil for a secret that does not exist.
	GetSecret(ctx context.Context, store entity.StoreID, name entity.SecretName) (*entity.Secret, error)
	InsertSecret(ctx context.Context, secret entity.Secret) error
	UpdateLabels(ctx context.Context, store entity.StoreID, name entity.SecretName, labels entity.Metadata) (bool, error)
	DeleteSecret(ctx context.Context, store entity.StoreID, name entity.SecretName) (bool, error)

	ListVersions(ctx context.Context, store entity.StoreID, name entity.SecretName) ([]entity.Version, error)
	// GetVersion returns nil for a version that does not exist.
	GetVersion(ctx context.Context, store entity.StoreID, name entity.SecretName, number int64) (*entity.OwnVersion, error)
	// AppendVersion allocates the next number and writes the version the
	// callback seals under it, in one transaction.
	//
	// The number and the seal have to agree, because the number is bound into
	// the tag — so allocating it outside the write would let two concurrent
	// writers seal different payloads under one number.
	AppendVersion(ctx context.Context, store entity.StoreID, name entity.SecretName, seal SealWith) (entity.OwnVersion, error)

	KeyIDsInUse(ctx context.Context, store entity.StoreID) ([]string, error)
}

// SealWith seals a payload once the version number is known.
type SealWith func(number int64) (entity.OwnVersion, error)

// OwnStoreService is keyway's own Store.
//
// Exists so keyway runs with no cloud account at all, which is what makes a
// one-command quickstart possible — and it is why the key comes from config
// rather than an unseal flow: keyway is a dependency of other people's
// deployments, and a service needing a human present after every node
// eviction blocks deploys at 3am.
type OwnStoreService struct {
	storeID entity.StoreID
	repo    OwnStoreRepo
	keyring *entity.Keyring
}

// NewOwnStoreService mounts one own Store over its rows.
func NewOwnStoreService(storeID entity.StoreID, repo OwnStoreRepo, keyring *entity.Keyring) *OwnStoreService {
	return &OwnStoreService{storeID: storeID, repo: repo, keyring: keyring}
}

// KeysInUse is which key ids still have a version sealed under them.
//
// A rotation is finished when this returns only the active id. Dropping a key
// before then is exactly what makes a payload unopenable, so this is the
// question an operator needs answered before they do it.
func (s *OwnStoreService) KeysInUse(ctx context.Context) ([]string, error) {
	return s.repo.KeyIDsInUse(ctx, s.storeID)
}

func (s *OwnStoreService) requireExists(ctx context.Context, name entity.SecretName) (entity.Secret, error) {
	secret, err := s.repo.GetSecret(ctx, s.storeID, name)
	if err != nil {
		return entity.Secret{}, entity.Backend("looking up a secret", err)
	}
	if secret == nil {
		return entity.Secret{}, entity.ErrNotFound
	}
	return *secret, nil
}

// List implements entity.SecretManager.
func (s *OwnStoreService) List(ctx context.Context) ([]entity.Secret, error) {
	listed, err := s.repo.ListSecrets(ctx, s.storeID)
	if err != nil {
		return nil, entity.Backend("listing secrets", err)
	}
	return listed, nil
}

// Get implements entity.SecretManager.
func (s *OwnStoreService) Get(ctx context.Context, name entity.SecretName) (entity.Secret, error) {
	return s.requireExists(ctx, name)
}

// Versions implements entity.SecretManager.
func (s *OwnStoreService) Versions(ctx context.Context, name entity.SecretName) ([]entity.Version, error) {
	if _, err := s.requireExists(ctx, name); err != nil {
		return nil, err
	}
	versions, err := s.repo.ListVersions(ctx, s.storeID, name)
	if err != nil {
		return nil, entity.Backend("listing versions", err)
	}
	return versions, nil
}

// Access implements entity.SecretManager.
func (s *OwnStoreService) Access(ctx context.Context, name entity.SecretName, version entity.VersionID) ([]byte, error) {
	if _, err := s.requireExists(ctx, name); err != nil {
		return nil, err
	}

	var number int64
	if !version.IsLatest() {
		parsed, err := entity.ParseNumber(version)
		if err != nil {
			return nil, err
		}
		number = parsed
	} else {
		versions, err := s.repo.ListVersions(ctx, s.storeID, name)
		if err != nil {
			return nil, entity.Backend("resolving the latest version", err)
		}
		latest, ok := entity.Latest(versions)
		if !ok {
			return nil, &entity.NoSuchVersionError{Version: "latest"}
		}
		number, err = entity.ParseNumber(latest.ID)
		if err != nil {
			return nil, err
		}
	}

	stored, err := s.repo.GetVersion(ctx, s.storeID, name, number)
	if err != nil {
		return nil, entity.Backend("reading a version", err)
	}
	if stored == nil {
		return nil, &entity.NoSuchVersionError{Version: entity.NumberVersion(number)}
	}
	return stored.Open(s.keyring)
}

// SetLabels implements entity.SecretManager.
func (s *OwnStoreService) SetLabels(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	changed, err := s.repo.UpdateLabels(ctx, s.storeID, name, labels)
	if err != nil {
		return entity.Backend("setting labels", err)
	}
	if !changed {
		return entity.ErrNotFound
	}
	return nil
}

// Create implements entity.SecretManager.
//
// The "a name is required" check that used to open this method is now the
// SecretName constructor's, at the edge that reads the request: a name is
// validated once, where it arrives, rather than by each backend that
// receives it.
func (s *OwnStoreService) Create(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	err := s.repo.InsertSecret(ctx, entity.Secret{
		Store:  s.storeID,
		Name:   name,
		Labels: labels,
	})
	if err != nil {
		return entity.Backend("creating a secret", err)
	}
	return nil
}

// AddVersion implements entity.SecretManager.
func (s *OwnStoreService) AddVersion(ctx context.Context, name entity.SecretName, payload []byte) (entity.Version, error) {
	if _, err := s.requireExists(ctx, name); err != nil {
		return entity.Version{}, err
	}

	seal := func(number int64) (entity.OwnVersion, error) {
		return entity.SealOwnVersion(s.keyring, s.storeID, name, number, payload)
	}
	written, err := s.repo.AppendVersion(ctx, s.storeID, name, seal)
	if err != nil {
		return entity.Version{}, entity.Backend("writing a version", err)
	}
	return written.Describe(), nil
}

// Delete implements entity.SecretManager.
func (s *OwnStoreService) Delete(ctx context.Context, name entity.SecretName) error {
	removed, err := s.repo.DeleteSecret(ctx, s.storeID, name)
	if err != nil {
		return entity.Backend("deleting a secret", err)
	}
	if !removed {
		return entity.ErrNotFound
	}
	return nil
}
