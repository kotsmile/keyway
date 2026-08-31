// keyway's own Store, as rules.
//
// The one backend where keyway holds a payload rather than pointing at
// somebody else's. Everything here decides things; nothing here talks to a
// database. What a row looks like is the secrets infra package's business.

package entity

import (
	"math"
	"strconv"
)

// OwnVersion is one stored revision of a secret in keyway's own Store.
type OwnVersion struct {
	Store  StoreID
	Secret SecretName
	// Number is per secret and monotonic. Bound into the seal, so it and the
	// payload cannot drift apart.
	Number int64
	Sealed Sealed
	State  VersionState
}

// SealOwnVersion seals payload as the next version of a secret.
func SealOwnVersion(keyring *Keyring, store StoreID, secret SecretName, number int64, payload []byte) (OwnVersion, error) {
	sealed, err := keyring.Seal(payload, ownAAD(store, secret, number))
	if err != nil {
		return OwnVersion{}, Backend("sealing a payload", err)
	}
	return OwnVersion{
		Store:  store,
		Secret: secret,
		Number: number,
		Sealed: sealed,
		State:  VersionEnabled,
	}, nil
}

// Open opens this version's payload.
//
// It returns a NoSuchVersionError for a destroyed version — its payload is
// gone for good, and saying so is better than handing back whatever bytes a
// row still holds. Otherwise it fails when the key is not configured or the
// payload does not authenticate.
func (v OwnVersion) Open(keyring *Keyring) ([]byte, error) {
	if v.State == VersionDestroyed {
		return nil, &NoSuchVersionError{Version: NumberVersion(v.Number)}
	}
	opened, err := keyring.Open(v.Sealed, ownAAD(v.Store, v.Secret, v.Number))
	if err != nil {
		return nil, Backend("opening a sealed payload", err)
	}
	return opened, nil
}

// Describe is how this version reports itself to the rest of the system.
func (v OwnVersion) Describe() Version {
	return Version{
		ID:    NumberVersion(v.Number),
		State: v.State,
	}
}

// NumberVersion is how keyway's own Store spells a version id: the decimal
// number, which is also what the seal binds and what a caller may ask for
// back.
func NumberVersion(number int64) VersionID {
	return VersionID(strconv.FormatInt(number, 10))
}

// ownAAD is the identity bound into the tag, so a ciphertext lifted from one
// row into another fails to open rather than revealing the wrong value.
func ownAAD(store StoreID, secret SecretName, number int64) []byte {
	return AAD(store.String(), secret.String(), strconv.FormatInt(number, 10))
}

// Latest is which version an unqualified read resolves to: the newest that
// still has a payload.
func Latest(versions []Version) (Version, bool) {
	var best Version
	bestNumber := int64(math.MinInt64)
	found := false
	for _, v := range versions {
		if v.State != VersionEnabled {
			continue
		}
		// An unparseable id never beats a parseable one, but an enabled
		// version is still reported when it is all there is.
		number := int64(math.MinInt64)
		if parsed, err := strconv.ParseInt(v.ID.String(), 10, 64); err == nil {
			number = parsed
		}
		if !found || number >= bestNumber {
			best, bestNumber, found = v, number, true
		}
	}
	return best, found
}

// NextNumber is the number the next version takes.
//
// Derived from what exists rather than from a sequence, because the number is
// bound into the seal: the caller allocates and seals inside one transaction,
// so two concurrent writers cannot seal different payloads under one number.
func NextNumber(versions []Version) int64 {
	highest := int64(0)
	for _, v := range versions {
		if number, err := strconv.ParseInt(v.ID.String(), 10, 64); err == nil && number > highest {
			highest = number
		}
	}
	return highest + 1
}

// ParseNumber reads a version number a caller asked for.
//
// It fails when it is not a number this Store could have issued.
func ParseNumber(raw VersionID) (int64, error) {
	number, err := strconv.ParseInt(raw.String(), 10, 64)
	if err != nil {
		return 0, &NoSuchVersionError{Version: raw}
	}
	return number, nil
}
