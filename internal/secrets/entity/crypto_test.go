package entity

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	keyA = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	keyB = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

func ring(t *testing.T, active string, keys map[string]string) *Keyring {
	t.Helper()
	keyring, err := NewKeyring(active, keys)
	require.NoError(t, err, "a valid keyring")
	return keyring
}

func TestAPayloadRoundTrips(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	aad := AAD("local", "db-creds", "1")

	sealed, err := keyring.Seal([]byte("hunter2"), aad)
	require.NoError(t, err)
	opened, err := keyring.Open(sealed, aad)
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), opened)
}

func TestTheCiphertextDoesNotContainThePlaintext(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := keyring.Seal([]byte("hunter2"), []byte("aad"))
	require.NoError(t, err)
	assert.NotContains(t, string(sealed.Ciphertext), "hunter2")
}

func TestTwoSealsOfOneValueDiffer(t *testing.T) {
	// A fresh nonce per version. Equal ciphertexts would tell an observer
	// with read access to the table which secrets share a value.
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	first, err := keyring.Seal([]byte("same"), []byte("aad"))
	require.NoError(t, err)
	second, err := keyring.Seal([]byte("same"), []byte("aad"))
	require.NoError(t, err)

	assert.NotEqual(t, first.Nonce, second.Nonce)
	assert.NotEqual(t, first.Ciphertext, second.Ciphertext)
}

func TestATamperedCiphertextWillNotOpen(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := keyring.Seal([]byte("hunter2"), []byte("aad"))
	require.NoError(t, err)
	sealed.Ciphertext[0] ^= 0x01

	_, err = keyring.Open(sealed, []byte("aad"))
	assert.ErrorIs(t, err, ErrUnopenable)
}

func TestACiphertextMovedToAnotherSecretWillNotOpen(t *testing.T) {
	// The identity is bound into the tag, so a row lifted from one secret
	// into another fails rather than revealing the wrong value.
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := keyring.Seal([]byte("hunter2"), AAD("local", "db-creds", "1"))
	require.NoError(t, err)

	_, err = keyring.Open(sealed, AAD("local", "api-key", "1"))
	assert.ErrorIs(t, err, ErrUnopenable)
}

func TestAVersionSealedUnderARetiredKeyStillOpens(t *testing.T) {
	// The whole point of recording key_id per version: rotating the active
	// key must not make yesterday's payloads unreadable.
	old := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := old.Seal([]byte("hunter2"), []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, "v1", sealed.KeyID)

	rotated := ring(t, "v2", map[string]string{"v1": keyA, "v2": keyB})
	opened, err := rotated.Open(sealed, []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), opened)

	resealed, err := rotated.Seal([]byte("new"), []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, "v2", resealed.KeyID, "new payloads use the active key")
}

func TestDroppingAKeyThatIsStillInUseIsReportedAsSuch(t *testing.T) {
	old := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := old.Seal([]byte("hunter2"), []byte("aad"))
	require.NoError(t, err)

	without := ring(t, "v2", map[string]string{"v2": keyB})
	_, err = without.Open(sealed, []byte("aad"))
	var unknown *UnknownKeyError
	assert.ErrorAs(t, err, &unknown)
}

func TestAnActiveIDNamingNoKeyIsRefusedAtConstruction(t *testing.T) {
	// Caught at boot rather than on the first write.
	_, err := NewKeyring("v2", map[string]string{"v1": keyA})
	var unknown *UnknownKeyError
	assert.ErrorAs(t, err, &unknown)
}

func TestAKeyOfTheWrongLengthIsRefused(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := NewKeyring("v1", map[string]string{"v1": short})
	var bad *BadKeyError
	require.ErrorAs(t, err, &bad, "expected a bad key")
	assert.Contains(t, bad.Reason, "16 bytes", "reason was %q", bad.Reason)
}

func TestAKeyThatIsNotBase64IsRefused(t *testing.T) {
	_, err := NewKeyring("v1", map[string]string{"v1": "not base64!"})
	var bad *BadKeyError
	assert.ErrorAs(t, err, &bad)
}

func TestATruncatedNonceIsRefusedRatherThanPanicking(t *testing.T) {
	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed, err := keyring.Seal([]byte("hunter2"), []byte("aad"))
	require.NoError(t, err)
	sealed.Nonce = sealed.Nonce[:4]
	_, err = keyring.Open(sealed, []byte("aad"))
	assert.ErrorIs(t, err, ErrUnopenable)
}

// TestAGoldenRustCiphertextOpens pins the wire format to the Rust
// implementation's, byte for byte.
//
// The vector was generated with the exact crate versions the Rust server
// locks (aes-gcm 0.11.1 with aes 0.9.2, ghash 0.6.0, ctr 0.10.1): key keyA,
// nonce 00..0b, aad `local/db-creds@1` from crypto.rs's aad(), plaintext
// `hunter2`. The 23 bytes are the 7-byte ciphertext with the 16-byte tag
// appended, exactly as a Rust-written own_versions row stores them. If this
// test fails, the Go port can no longer decrypt what the Rust server sealed
// — that is format drift, and it must fail loudly.
func TestAGoldenRustCiphertextOpens(t *testing.T) {
	nonce, err := hex.DecodeString("000102030405060708090a0b")
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString("d3d3fb52458c3429b672e53a03e7e2dcb0a07551c47182")
	require.NoError(t, err)

	keyring := ring(t, "v1", map[string]string{"v1": keyA})
	sealed := Sealed{KeyID: "v1", Nonce: nonce, Ciphertext: ciphertext}

	opened, err := keyring.Open(sealed, AAD("local", "db-creds", "1"))
	require.NoError(t, err, "a ciphertext the Rust server wrote must open")
	assert.Equal(t, []byte("hunter2"), opened)

	// And the other direction: with the same nonce, Go produces the very
	// bytes Rust produced — so a row the Go server seals opens under Rust.
	// Seal() draws a random nonce, so the deterministic check goes through
	// the same cipher construction Seal uses.
	aead, err := decodeKey("v1", keyA)
	require.NoError(t, err)
	assert.Equal(t, ciphertext,
		aead.Seal(nil, nonce, []byte("hunter2"), AAD("local", "db-creds", "1")),
		"Go and Rust must agree byte for byte")
}
