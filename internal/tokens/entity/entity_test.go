// Ported test for test from the Rust tokens/entity.rs, plus the golden test
// pinning the stored format across the Rust-to-Go cutover. An internal test
// package deliberately, so the golden test can pin hashSecret itself.
package entity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minted returns the plaintext EXPOSED, because the assertions below are
// about the bytes on the wire. Everywhere else in the codebase a Plaintext
// prints as `kw-<redacted>`, which is the point of the type.
func minted(t *testing.T) (StoredToken, string) {
	t.Helper()
	name, err := NewName("eso prod")
	require.NoError(t, err, "a name")
	stored, plaintext, err := Mint("alice", name, nil)
	require.NoError(t, err, "mints")
	return stored, plaintext.Expose()
}

func mustSplit(t *testing.T, plaintext string) (ID, string) {
	t.Helper()
	id, secret, ok := Split(plaintext)
	require.True(t, ok, "%s splits", plaintext)
	return id, secret
}

// TestAGoldenRustMintedTokenStillVerifies pins the stored format across the
// cutover (ADR-0006). The vector was minted by the Rust minting code itself —
// the hex/base64url/sha256 calls of tokens/entity.rs run with fixed bytes in
// place of getrandom — and the hash is independently confirmed by
// `shasum -a 256`. If this test fails, tokens in a live deployment's tokens
// table stop working; nothing here is tunable.
func TestAGoldenRustMintedTokenStillVerifies(t *testing.T) {
	const (
		goldenID = "00112233aabbccdd"
		// The secret half deliberately begins with `----____`: the separator
		// character inside the base64url alphabet, the ambiguity the hex id
		// exists to resolve.
		goldenSecret    = "----____AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk"
		goldenPlaintext = "kw-" + goldenID + "-" + goldenSecret
		goldenHashHex   = "e07767391987b5b8e95606b3cf66afd95be131c09e4c006bf81e0961e33eb333"
	)
	goldenHash, err := hex.DecodeString(goldenHashHex)
	require.NoError(t, err)

	// The Go hash of the secret HALF AS TEXT must be the Rust one.
	assert.Equal(t, goldenHash, hashSecret(goldenSecret))

	// And a stored row holding the Rust hash must admit the Rust plaintext.
	id, secret := mustSplit(t, goldenPlaintext)
	assert.Equal(t, ID(goldenID), id)
	assert.Equal(t, goldenSecret, secret)
	stored := StoredToken{ID: ID(goldenID), Hash: goldenHash}
	assert.NoError(t, stored.Admits(secret, time.Now()))
}

// TestTheMintedShapeIsPinned is the other half of the golden test: what Go
// mints must be indistinguishable in shape from what Rust minted, so a
// rollback to the Rust server keeps verifying Go-minted rows too.
func TestTheMintedShapeIsPinned(t *testing.T) {
	shape := regexp.MustCompile(`^kw-[0-9a-f]{16}-[A-Za-z0-9_-]{43}$`)
	stored, plaintext := minted(t)
	assert.Regexp(t, shape, plaintext)
	assert.Len(t, stored.Hash, 32, "sha256")
	_, secret := mustSplit(t, plaintext)
	assert.Equal(t, hashSecret(secret), stored.Hash)
}

func TestAMintedTokenVerifiesAgainstItsOwnHash(t *testing.T) {
	stored, plaintext := minted(t)
	id, secret := mustSplit(t, plaintext)

	assert.Equal(t, stored.ID, id)
	assert.NoError(t, stored.Admits(secret, time.Now()))
}

func TestAnotherSecretDoesNotVerify(t *testing.T) {
	stored, _ := minted(t)
	assert.ErrorIs(t, stored.Admits("wrong", time.Now()), WrongSecret)
}

func TestAnExpiredTokenIsRefusedEvenWithTheRightSecret(t *testing.T) {
	stored, plaintext := minted(t)
	expiry := time.Now().Add(-time.Second)
	stored.ExpiresAt = &expiry
	_, secret := mustSplit(t, plaintext)

	assert.ErrorIs(t, stored.Admits(secret, time.Now()), Expired)
}

func TestATokenWithNoExpiryNeverExpires(t *testing.T) {
	// Deliberate, for the caller this exists for: an expiry on the credential
	// a reconcile loop presents is an outage scheduled for a day nobody
	// picked.
	stored, plaintext := minted(t)
	_, secret := mustSplit(t, plaintext)

	farFuture := time.Now().Add(3650 * 24 * time.Hour)
	assert.NoError(t, stored.Admits(secret, farFuture))
}

func TestANameIsRequired(t *testing.T) {
	// The rule moved from Mint onto the Name type — it is read at the edge
	// now, so a request without a usable name is refused before any entropy
	// or any row is generated. What it refuses is unchanged.
	_, err := NewName("   ")
	assert.ErrorIs(t, err, ErrNameRequired)

	long := make([]byte, MaxName+1)
	for i := range long {
		long[i] = 'x'
	}
	_, err = NewName(string(long))
	assert.ErrorIs(t, err, ErrNameRequired)
}

func TestANameIsTrimmedRatherThanRefusedForItsWhitespace(t *testing.T) {
	name, err := NewName("  eso prod  ")
	require.NoError(t, err)
	assert.Equal(t, Name("eso prod"), name)
}

func TestATokenIDIsHexOrItIsNotAnID(t *testing.T) {
	// The same grammar Split relies on: an id that is not hex could never
	// have been minted, so a route holding one is holding a probe.
	for _, bad := range []string{"", "zzz", "kw-00", "00-11", "abcdefg"} {
		_, err := ParseID(bad)
		assert.ErrorIs(t, err, ErrNotAnID, "%q is not an id", bad)
	}
	id, err := ParseID("00112233aabbccdd")
	require.NoError(t, err)
	assert.Equal(t, ID("00112233aabbccdd"), id)
}

func TestAPlaintextRedactsItselfEverywhereButTheResponse(t *testing.T) {
	// A minted token exists once, in one response body. The type is what
	// keeps it out of every log line, %v and error string on the way there.
	plaintext := Plaintext("kw-00112233aabbccdd-hunter2")
	assert.Equal(t, Redacted, plaintext.String())
	assert.Equal(t, Redacted, fmt.Sprintf("%v", plaintext))
	assert.Equal(t, Redacted, plaintext.LogValue().String())
	assert.NotContains(t, fmt.Sprintf("%v", plaintext), "hunter2")

	// And Expose still hands over the real thing, for the one caller that
	// must write it out.
	assert.Equal(t, "kw-00112233aabbccdd-hunter2", plaintext.Expose())
}

func TestPlaintextRedactsThroughSlog(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	logger.Info("minted", "token", Plaintext("kw-00112233aabbccdd-hunter2"))
	assert.NotContains(t, out.String(), "hunter2")
	assert.Contains(t, out.String(), Redacted)
}

func TestThePlaintextIsURLSafe(t *testing.T) {
	// A token goes into env vars, YAML and URLs. A `/` or `+` in it is a bug
	// report from somebody whose CI mangled it.
	urlSafe := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for range 32 {
		_, plaintext := minted(t)
		assert.Regexp(t, urlSafe, plaintext, "%s is not url-safe", plaintext)
	}
}

func TestEveryMintedTokenVerifiesAgainstItsOwnHash(t *testing.T) {
	// A REGRESSION TEST, and it has to loop. The id was base64url once, which
	// contains `-` — the same character that separates the halves. Roughly
	// one token in three split in the wrong place and could not be used at
	// all, and a single round trip missed it two times in three.
	for range 512 {
		stored, plaintext := minted(t)
		id, secret := mustSplit(t, plaintext)
		assert.Equal(t, stored.ID, id, "%s", plaintext)
		assert.NoError(t, stored.Admits(secret, time.Now()), "%s did not verify", plaintext)
	}
}

func TestAnIDNeverContainsTheSeparator(t *testing.T) {
	for range 512 {
		stored, _ := minted(t)
		assert.NotContains(t, stored.ID, "-", "%s would split in the wrong place", stored.ID)
	}
}

func TestTokensDoNotRepeat(t *testing.T) {
	first, _ := minted(t)
	second, _ := minted(t)
	assert.NotEqual(t, first.ID, second.ID)
	assert.NotEqual(t, first.Hash, second.Hash)
}

func TestSomethingThatIsNotATokenDoesNotSplit(t *testing.T) {
	for _, bad := range []string{
		"",
		"kw",
		"kw-",
		"kw-onlyid",
		"kw--secret",
		"kw-id-",
		"lkr-id-secret",
		"hunter2",
	} {
		_, _, ok := Split(bad)
		assert.False(t, ok, "%q should not split", bad)
	}
}

func TestASecretContainingADashSurvivesTheSplit(t *testing.T) {
	// The secret half is base64url and may contain `-`; everything after the
	// first separator is the secret.
	id, secret := mustSplit(t, "kw-aa-bb-cc")
	assert.Equal(t, ID("aa"), id)
	assert.Equal(t, "bb-cc", secret)
}

func TestAnIDThatIsNotHexIsRefused(t *testing.T) {
	// Nothing keyway minted looks like this, so it is a probe.
	_, _, ok := Split("kw-zzz-secret")
	assert.False(t, ok)
}

func TestComparisonRejectsADifferentLength(t *testing.T) {
	assert.False(t, constantTimeEq([]byte("abc"), []byte("abcd")))
	assert.True(t, constantTimeEq([]byte("abc"), []byte("abc")))
}
