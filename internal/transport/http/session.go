// The browser session.
//
// Everything the session needs lives in an encrypted cookie rather than in
// server memory: keyway runs several replicas, and a session held in one of
// them is a session that vanishes on a rolling deploy.
//
// The cookie is encrypted AND authenticated, not merely signed, because it
// carries the caller's groups, which is a fact about the organisation and not
// something to hand out in readable form.
//
// One deliberate deviation from the Rust server (ADR-0006 permits it): the
// ciphertext format is this package's own AES-256-GCM sealing, not
// axum-extra's private-cookie format. The key config, the payload JSON and
// the cookie attributes all carry over; the sealed bytes do not, so the
// cutover signs every browser out once — which is also what rotating the key
// has always done.

package http

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
)

// SessionCookie is the session cookie's name. Not configurable: it is a
// property of this service's identity rather than of a deployment, and a name
// somebody could change is a name somebody could change to another service's.
const SessionCookie = "keyway_session"

// Session is who a browser is signed in as.
//
// The json tags mirror the Rust serde fields; the value is sealed, but the
// payload shape is still a contract with the code reading it back.
type Session struct {
	Handle string   `json:"handle"`
	Groups []string `json:"groups"`
	Roles  []string `json:"roles"`
	// ExpiresAt is checked on every request. A cookie's own Max-Age is a hint
	// the client is free to ignore, so the expiry has to be inside the sealed
	// value as well.
	ExpiresAt time.Time `json:"expires_at"`
}

// IsLive is whether this session still stands.
func (s Session) IsLive(now time.Time) bool {
	return s.ExpiresAt.After(now)
}

// Actor is who this session is, as the rest of the system reasons about
// callers.
//
// A role name nothing in this build can interpret grants nothing: a realm may
// hold roles from other systems, and ignoring an unreadable word is the only
// safe reading of it.
func (s Session) Actor() identityentity.Actor {
	roles := make([]identityentity.Role, 0, len(s.Roles))
	for _, word := range s.Roles {
		if role, known := identityentity.ParseRole(word); known {
			roles = append(roles, role)
		}
	}
	return identityentity.NewActor(s.Handle, s.Groups, roles)
}

// Cookie is the cookie carrying this session, sealed.
func (s Session) Cookie(codec *Codec, hours int64) (*http.Cookie, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("sealing the session: %w", err)
	}
	return SealedCookie(codec, SessionCookie, payload, time.Duration(hours)*time.Hour), nil
}

// SessionFromCookie reads one back, if the value opens and parses.
func SessionFromCookie(codec *Codec, value string) (Session, bool) {
	payload, ok := codec.Open(SessionCookie, value)
	if !ok {
		return Session{}, false
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return Session{}, false
	}
	return session, true
}

// SealedCookie builds a cookie the way every keyway cookie is built: sealed,
// HttpOnly, Secure, and Lax rather than Strict — an issuer redirects back
// with a GET, and Strict would withhold the cookie on exactly that request.
func SealedCookie(codec *Codec, name string, payload []byte, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    codec.Seal(name, payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	}
}

// RemovalCookie is the cookie that deletes one.
//
// It carries the same Path the set cookie did — a removal on a different path
// is a removal the browser ignores.
func RemovalCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// Codec seals and opens cookie values.
//
// AES-256-GCM under the second half of the configured 64-byte master key —
// the same half axum-extra used for encryption, so a deployment's existing
// oidc.session_key keeps working unchanged. The cookie's NAME is bound in as
// associated data: a value lifted out of one cookie must not open as another.
type Codec struct {
	aead cipher.AEAD
}

// KeyLengthError is a session key shorter than the config contract requires.
type KeyLengthError struct {
	Got int
}

func (e *KeyLengthError) Error() string {
	return fmt.Sprintf("oidc.session_key decodes to %d bytes; at least 64 are needed", e.Got)
}

// NewCodec builds a codec over a master key of at least 64 bytes.
func NewCodec(master []byte) (*Codec, error) {
	if len(master) < 64 {
		return nil, &KeyLengthError{Got: len(master)}
	}
	block, err := aes.NewCipher(master[32:64])
	if err != nil {
		return nil, fmt.Errorf("building the cookie cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("building the cookie cipher: %w", err)
	}
	return &Codec{aead: aead}, nil
}

// GenerateKey is a fresh random master key, for a run with none configured.
// Sessions sealed under it die with the process, which is the loudly-warned
// tradeoff of not configuring one.
func GenerateKey() []byte {
	master := make([]byte, 64)
	if _, err := rand.Read(master); err != nil {
		panic(err) // Documented to never fail since Go 1.24.
	}
	return master
}

// Seal encrypts a payload into a cookie value: base64url(nonce || ciphertext).
func (c *Codec) Seal(name string, payload []byte) string {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // Documented to never fail since Go 1.24.
	}
	sealed := c.aead.Seal(nonce, nonce, payload, []byte(name))
	return base64.RawURLEncoding.EncodeToString(sealed)
}

// Open decrypts a cookie value. Anything that does not open — tampered,
// truncated, sealed under another key or another name — is simply not a
// value, never an error worth distinguishing.
func (c *Codec) Open(name, value string) ([]byte, bool) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) < c.aead.NonceSize() {
		return nil, false
	}
	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	payload, err := c.aead.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return nil, false
	}
	return payload, true
}
