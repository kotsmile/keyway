package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCodec(t *testing.T) *Codec {
	t.Helper()
	codec, err := NewCodec(GenerateKey())
	require.NoError(t, err)
	return codec
}

func session(expiresAt time.Time) Session {
	return Session{
		Handle:    "alice",
		Groups:    []string{"SRE"},
		Roles:     []string{"create"},
		ExpiresAt: expiresAt,
	}
}

func TestASessionRoundTripsThroughItsCookie(t *testing.T) {
	t.Parallel()
	codec := testCodec(t)

	original := session(time.Now().Add(8 * time.Hour))
	cookie, err := original.Cookie(codec, 8)
	require.NoError(t, err)

	read, ok := SessionFromCookie(codec, cookie.Value)
	require.True(t, ok, "reads back")
	assert.Equal(t, "alice", read.Handle)
	assert.Equal(t, []string{"SRE"}, read.Groups)
	assert.True(t, read.Actor().MayCreate())
}

func TestAnExpiredSessionIsNotLive(t *testing.T) {
	t.Parallel()
	// The cookie's own Max-Age is a hint a client may ignore, so the expiry is
	// checked from inside the sealed value too.
	now := time.Now()
	assert.False(t, session(now.Add(-time.Second)).IsLive(now))
	assert.True(t, session(now.Add(time.Hour)).IsLive(now))
}

func TestARoleThisBuildCannotReadGrantsNothing(t *testing.T) {
	t.Parallel()
	// A realm may hold roles from other systems. Ignoring a name nothing here
	// can interpret is the only safe reading of it.
	s := session(time.Now().Add(time.Hour))
	s.Roles = []string{"some-other-system:admin"}

	actor := s.Actor()
	assert.False(t, actor.IsAdmin())
	assert.False(t, actor.MayCreate())
}

func TestTheCookieIsNotReadableByScriptAndNotSentCrossSite(t *testing.T) {
	t.Parallel()
	cookie, err := session(time.Now().Add(8*time.Hour)).Cookie(testCodec(t), 8)
	require.NoError(t, err)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, int((8 * time.Hour).Seconds()), cookie.MaxAge)
}

func TestATamperedValueDoesNotOpen(t *testing.T) {
	t.Parallel()
	codec := testCodec(t)
	sealed := codec.Seal(SessionCookie, []byte(`{"handle":"alice"}`))

	// Flip one character. Base64url keeps the string decodable while the AEAD
	// tag no longer matches.
	tampered := []byte(sealed)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	_, ok := codec.Open(SessionCookie, string(tampered))
	assert.False(t, ok, "a modified ciphertext must not open")
}

func TestAValueSealedForOneCookieDoesNotOpenAsAnother(t *testing.T) {
	t.Parallel()
	// The cookie's name is bound in as associated data: a pending-login value
	// lifted into the session cookie must be nothing, not a session.
	codec := testCodec(t)
	sealed := codec.Seal("keyway_pending", []byte(`{"csrf":"x"}`))
	_, ok := codec.Open(SessionCookie, sealed)
	assert.False(t, ok)
}

func TestAValueSealedUnderAnotherKeyDoesNotOpen(t *testing.T) {
	t.Parallel()
	// Rotating oidc.session_key signs everybody out — the sealed values simply
	// stop opening, exactly as the Rust private cookies did.
	first, second := testCodec(t), testCodec(t)
	sealed := first.Seal(SessionCookie, []byte(`{"handle":"alice"}`))
	_, ok := second.Open(SessionCookie, sealed)
	assert.False(t, ok)
}

func TestAShortMasterKeyIsRefusedWithTheRustWording(t *testing.T) {
	t.Parallel()
	// The config contract carries over: at least 64 decoded bytes, and the
	// refusal says how many arrived.
	_, err := NewCodec(make([]byte, 32))
	require.Error(t, err)
	assert.Equal(t, "oidc.session_key decodes to 32 bytes; at least 64 are needed", err.Error())
}

func TestRemovalCookieDeletesOnTheSamePath(t *testing.T) {
	t.Parallel()
	removal := RemovalCookie(SessionCookie)
	assert.Equal(t, "/", removal.Path, "a removal on a different path is one the browser ignores")
	assert.Negative(t, removal.MaxAge)
	assert.Empty(t, removal.Value)
}
