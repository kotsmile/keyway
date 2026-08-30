// Package entity is the token format, and what makes a presented one
// acceptable.
//
// No I/O: minting produces bytes and a hash, verification compares them. What
// a row looks like is the infra package's business.
//
// The format is the one the Rust server minted and MUST stay byte-compatible
// with it: every `kw-` token in a live deployment's tokens table has to keep
// verifying across the cutover (ADR-0006). The stored shape is pinned by a
// golden test minted with the Rust crates themselves.
package entity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Prefix is what every keyway token starts with, so one that turns up in a
// log or a repository names the system it opens without anybody having to
// recognise the shape.
const Prefix = "kw"

// idBytes is the public half. Not a secret: it is the lookup key, and what an
// audit row names.
//
// Rendered as HEX rather than base64url, which is the whole reason the format
// is unambiguous: `-` is the separator, base64url contains `-`, and an id
// carrying one would split in the wrong place and fail to verify against its
// own hash. Hex cannot, so the first `-` after the prefix is always the
// separator.
const idBytes = 8

// secretBytes is the secret half.
const secretBytes = 32

// MaxName is long enough for "eso — payment-bot prod", short enough that the
// list stays a list.
const MaxName = 80

// Token is one issued token as a caller sees it. The plaintext is
// deliberately absent: it exists once, in the response that created it.
//
// The subject is never serialised — the Rust struct skipped it too.
type Token struct {
	ID        string     `json:"id"`
	Subject   string     `json:"-"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"`
}

// StoredToken is one issued token as storage holds it — the hash included.
type StoredToken struct {
	ID        string
	Hash      []byte
	Subject   string
	Name      string
	CreatedAt time.Time
	ExpiresAt *time.Time
	LastUsed  *time.Time
}

// Admits is whether the secret half presented is this token's, and it is
// still live.
//
// A refusal is a Rejected saying which, for a log line. A caller reports all
// of them identically.
func (t StoredToken) Admits(secret string, now time.Time) error {
	if !constantTimeEq(t.Hash, hashSecret(secret)) {
		return WrongSecret
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return Expired
	}
	return nil
}

// Rejected is why a presented token was not accepted.
//
// Distinguished here so a log line can say what happened, never so a response
// can. It is an error so a transport can pull it out of a Verify failure with
// errors.Is and answer 401 uniformly.
type Rejected int

const (
	// Malformed is not `kw-<id>-<secret>`.
	Malformed Rejected = iota + 1
	// Unknown is no token with that id.
	Unknown
	// WrongSecret is the id exists but the secret half does not match.
	WrongSecret
	// Expired is past its expiry.
	Expired
)

func (r Rejected) Error() string {
	switch r {
	case Malformed:
		return "token rejected: malformed"
	case Unknown:
		return "token rejected: unknown id"
	case WrongSecret:
		return "token rejected: wrong secret"
	case Expired:
		return "token rejected: expired"
	}
	return fmt.Sprintf("token rejected: Rejected(%d)", int(r))
}

// Minted is a newly minted token: the row, and the plaintext that will never
// exist again.
//
// The Rust side zeroized the plaintext on drop; Go's GC moves and copies
// strings, so pretending to scrub one would be theatre. The discipline is the
// same either way: it goes into one response body and nowhere else.
type Minted struct {
	Token Token
	// Plaintext goes into one response body and nowhere else.
	Plaintext string
}

// ErrNameRequired is a missing or over-long token name.
var ErrNameRequired = fmt.Errorf("a name is required, up to %d characters", MaxName)

// Mint generates a token for `subject`.
//
// Returns what to store and what to show once. CreatedAt is left zero for
// storage to fill, which is the only thing that can say when the row was
// written.
func Mint(subject, name string, expiresAt *time.Time) (StoredToken, string, error) {
	name = strings.TrimSpace(name)
	// Required, not defaulted to something like "token": the name is the only
	// thing that answers "can I delete this one" in six months, and a list of
	// identical defaults answers nothing.
	if name == "" || len(name) > MaxName {
		return StoredToken{}, "", ErrNameRequired
	}

	idRaw := make([]byte, idBytes)
	if _, err := rand.Read(idRaw); err != nil {
		return StoredToken{}, "", fmt.Errorf("generating a token: %w", err)
	}
	secretRaw := make([]byte, secretBytes)
	if _, err := rand.Read(secretRaw); err != nil {
		return StoredToken{}, "", fmt.Errorf("generating a token: %w", err)
	}

	id := hex.EncodeToString(idRaw)
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)

	return StoredToken{
		ID:        id,
		Hash:      hashSecret(secret),
		Subject:   subject,
		Name:      name,
		ExpiresAt: expiresAt,
	}, Prefix + "-" + id + "-" + secret, nil
}

// Split splits `kw-<id>-<secret>`.
//
// On the FIRST `-` after the prefix, which is only unambiguous because the id
// is hex. The secret half is base64url and may well contain `-`; that is
// fine, since everything after the separator is the secret.
func Split(presented string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(presented, Prefix+"-")
	if !found {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, "-")
	if !found || id == "" || secret == "" || !isHex(id) {
		return "", "", false
	}
	return id, secret, true
}

func isHex(s string) bool {
	for _, c := range []byte(s) {
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// hashSecret is sha256 over the secret half AS TEXT — the base64url string,
// not the bytes it encodes. That is what the Rust server stored, and it is
// load-bearing: hashing the decoded bytes instead would refuse every token
// already minted.
func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// constantTimeEq compares in time independent of where the first difference
// is, so a caller cannot learn a hash a byte at a time.
func constantTimeEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
