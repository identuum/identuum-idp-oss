package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomHexKey returns a fresh 64-char (32-byte) hex-encoded AES key.
// Shared by every rotation test so each test gets an independent key set.
func randomHexKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return hex.EncodeToString(raw)
}

func TestNewCryptoService(t *testing.T) {
	// Valid key (32 bytes = 64 hex chars)
	validKey := make([]byte, 32)
	rand.Read(validKey)
	hexKey := hex.EncodeToString(validKey)

	svc, err := NewCryptoService(hexKey)
	require.NoError(t, err)
	assert.NotNil(t, svc)
	assert.Equal(t, validKey, svc.active.material)
	assert.NotEmpty(t, svc.active.id)
	assert.Len(t, svc.active.id, 16, "key id is 16 hex chars (first 8 bytes of sha256)")
	assert.Empty(t, svc.previous, "no previous keys at construction")

	// Invalid hex
	_, err = NewCryptoService("zzzzz")
	assert.ErrorContains(t, err, "invalid hex key")

	// Invalid length (16 bytes = 32 hex chars)
	invalidKey := make([]byte, 16)
	rand.Read(invalidKey)
	_, err = NewCryptoService(hex.EncodeToString(invalidKey))
	assert.ErrorContains(t, err, "key must be 32 bytes")
}

func TestCryptoService_EncryptDecrypt(t *testing.T) {
	svc, err := NewCryptoService(randomHexKey(t))
	require.NoError(t, err)

	plaintext := "super-secret-password-123"

	ciphertext, err := svc.Encrypt(plaintext)
	require.NoError(t, err)

	// Every new Encrypt emits v2 with the active key id embedded.
	assert.True(t, strings.HasPrefix(ciphertext, "v2:"),
		"new ciphertexts must be v2-formatted, got: %s", ciphertext)
	assert.Contains(t, ciphertext, svc.ActiveKeyID())

	decrypted, err := svc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestCryptoService_DecryptV1_BackwardCompat — v1: ciphertexts produced by
// the pre-versioning codebase must keep decrypting after the upgrade, or
// every row with a v1 seal (MFA secrets, OIDC state, webhook secrets...)
// becomes unreadable on deploy. Craft a v1-shaped token manually so this
// test is independent of the current Encrypt output.
func TestCryptoService_DecryptV1_BackwardCompat(t *testing.T) {
	hexKey := randomHexKey(t)
	svc, err := NewCryptoService(hexKey)
	require.NoError(t, err)

	plaintext := "v1-era-ciphertext"
	keyBytes, _ := hex.DecodeString(hexKey)
	v1Ciphertext := craftV1Ciphertext(t, keyBytes, plaintext)

	decrypted, err := svc.Decrypt(v1Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestCryptoService_DecryptLegacy_StdEncoding covers the oldest shape:
// no version prefix, StdEncoding base64. Present on rows that pre-date
// the v1 rollout. Once no row remains in this shape the fallback can be
// removed in a future cycle.
func TestCryptoService_DecryptLegacy_StdEncoding(t *testing.T) {
	hexKey := randomHexKey(t)
	svc, _ := NewCryptoService(hexKey)
	keyBytes, _ := hex.DecodeString(hexKey)

	plaintext := "legacy-secret-data"
	block, _ := aes.NewCipher(keyBytes)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	enc := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	legacyCiphertext := base64.StdEncoding.EncodeToString(enc)

	decrypted, err := svc.Decrypt(legacyCiphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCryptoService_DecryptErrors(t *testing.T) {
	svc, _ := NewCryptoService(randomHexKey(t))

	// Invalid base64
	_, err := svc.Decrypt("v1:not-base^64")
	assert.ErrorContains(t, err, "failed to decode ciphertext")

	// Ciphertext too short (valid base64, but not enough bytes for nonce).
	// Unkeyed path tries the active key and fails with ciphertext-too-short.
	shortData := base64.RawURLEncoding.EncodeToString([]byte("short"))
	_, err = svc.Decrypt("v1:" + shortData)
	assert.ErrorContains(t, err, "ciphertext too short")

	// Bad cipher (tampered) — v1 payload with the tag flipped.
	block, _ := aes.NewCipher(svc.active.material)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	enc := aesGCM.Seal(nonce, nonce, []byte("test"), nil)
	enc[len(enc)-1] ^= 0xff // Tamper with last byte
	tamperedB64 := "v1:" + base64.RawURLEncoding.EncodeToString(enc)

	_, err = svc.Decrypt(tamperedB64)
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	// v2 with a missing key-id separator is a format error — no fallback.
	_, err = svc.Decrypt("v2:just-a-thing-with-no-separator-and-no-colon")
	assert.ErrorContains(t, err, "missing key id separator")

	// v2 referencing an unknown key id is a permanent failure — the caller
	// must NOT see a retry loop across previous keys (v2 carries its own id).
	_, err = svc.Decrypt("v2:deadbeefdeadbeef:" + base64.RawURLEncoding.EncodeToString(enc))
	assert.ErrorContains(t, err, "unknown key id")
}

// TestCryptoService_SwapActive_NoOpForSameKey — the watcher will call
// SwapActive on every poll cycle; when Vault returns the same value
// (no rotation happened) the swap MUST be cheap and non-destructive.
func TestCryptoService_SwapActive_NoOpForSameKey(t *testing.T) {
	hexKey := randomHexKey(t)
	svc, _ := NewCryptoService(hexKey)
	initialID := svc.ActiveKeyID()

	oldID, newID, swapped, err := svc.SwapActive(hexKey)
	require.NoError(t, err)
	assert.False(t, swapped, "same key must not count as a swap")
	assert.Equal(t, initialID, oldID)
	assert.Equal(t, initialID, newID)
	assert.Empty(t, svc.PreviousKeyIDs(), "same-key swap must not demote the active key")
}

// TestCryptoService_SwapActive_RotatesAndPreservesOldDecrypt pins the
// whole point of rotation: a ciphertext sealed under the old key must
// keep decrypting after the rotation, AND new ciphertexts must use the
// new key. This is the load-bearing invariant of live rotation.
func TestCryptoService_SwapActive_RotatesAndPreservesOldDecrypt(t *testing.T) {
	oldHex := randomHexKey(t)
	svc, _ := NewCryptoService(oldHex)
	oldID := svc.ActiveKeyID()

	// Seal a secret under the old key — this is the "existing row" in DB.
	sealed, err := svc.Encrypt("mfa-seed-for-user-1")
	require.NoError(t, err)
	require.Contains(t, sealed, oldID)

	// Rotate.
	newHex := randomHexKey(t)
	fromID, toID, swapped, err := svc.SwapActive(newHex)
	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Equal(t, oldID, fromID)
	assert.NotEqual(t, oldID, toID)
	assert.Equal(t, toID, svc.ActiveKeyID())
	assert.Contains(t, svc.PreviousKeyIDs(), oldID,
		"the previous active must be retained for legacy decrypts")

	// Old ciphertext still decrypts — this is the customer promise.
	decrypted, err := svc.Decrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, "mfa-seed-for-user-1", decrypted)

	// New writes use the new key id.
	newSealed, err := svc.Encrypt("mfa-seed-for-user-2")
	require.NoError(t, err)
	assert.Contains(t, newSealed, toID)
	assert.NotContains(t, newSealed, oldID)
}

// TestCryptoService_SwapActive_V1FallbackAfterRotation — v1 ciphertexts
// have no embedded key id. After a rotation the active key has changed,
// so decrypt must try the previous pool. This test pins that the v1
// retry loop actually kicks in.
func TestCryptoService_SwapActive_V1FallbackAfterRotation(t *testing.T) {
	oldHex := randomHexKey(t)
	oldBytes, _ := hex.DecodeString(oldHex)
	svc, _ := NewCryptoService(oldHex)

	// Craft a v1 ciphertext under the original key (simulates legacy row).
	v1Sealed := craftV1Ciphertext(t, oldBytes, "legacy-mfa-secret")

	// Rotate to a brand-new key the v1 ciphertext was never encrypted under.
	_, _, _, err := svc.SwapActive(randomHexKey(t))
	require.NoError(t, err)

	// Decrypt must fall through to the previous pool and succeed.
	decrypted, err := svc.Decrypt(v1Sealed)
	require.NoError(t, err)
	assert.Equal(t, "legacy-mfa-secret", decrypted)
}

// TestCryptoService_SwapActive_InvalidHexRejected — a SwapActive that
// rejects bad input must NOT mutate state. If the watcher hands the
// service a corrupted secret, the service stays on the previous good key.
func TestCryptoService_SwapActive_InvalidHexRejected(t *testing.T) {
	svc, _ := NewCryptoService(randomHexKey(t))
	beforeID := svc.ActiveKeyID()

	_, _, swapped, err := svc.SwapActive("not-hex")
	assert.Error(t, err)
	assert.False(t, swapped)
	assert.Equal(t, beforeID, svc.ActiveKeyID(), "invalid swap must not alter active key")
	assert.Empty(t, svc.PreviousKeyIDs())
}

// TestCryptoService_Concurrent_EncryptDuringSwap — the watcher calls
// SwapActive while request goroutines are mid-Encrypt / mid-Decrypt. The
// sync.RWMutex guarantees consistency; this test stresses it by running
// concurrent ops and asserting every operation produces a round-trippable
// result (i.e. no half-swapped state).
func TestCryptoService_Concurrent_EncryptDuringSwap(t *testing.T) {
	svc, _ := NewCryptoService(randomHexKey(t))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 encrypt/decrypt workers racing forever until stop is closed.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ct, err := svc.Encrypt("payload")
					if err != nil {
						t.Errorf("encrypt: %v", err)
						return
					}
					pt, err := svc.Decrypt(ct)
					if err != nil {
						t.Errorf("decrypt: %v", err)
						return
					}
					if pt != "payload" {
						t.Errorf("round-trip mismatch: got %q", pt)
						return
					}
				}
			}
		}()
	}

	// One rotator firing swaps as fast as it can — forces SwapActive to
	// interleave with many Encrypt / Decrypt calls.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _, _, err := svc.SwapActive(randomHexKey(t))
			if err != nil {
				t.Errorf("swap: %v", err)
				return
			}
		}
	}()

	// Let the workers run for a short but meaningful window.
	for i := 0; i < 50; i++ {
		_, _, _, _ = svc.SwapActive(randomHexKey(t))
	}
	close(stop)
	wg.Wait()
}

// craftV1Ciphertext helper — produces a v1: formatted ciphertext directly
// under the given key, used by tests that need to simulate rows written
// before versioning was introduced.
func craftV1Ciphertext(t *testing.T, keyBytes []byte, plaintext string) string {
	t.Helper()
	block, err := aes.NewCipher(keyBytes)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	enc := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v1:" + base64.RawURLEncoding.EncodeToString(enc)
}

func FuzzCryptoService_Decrypt(f *testing.F) {
	svc, _ := NewCryptoService(randomHexKeyFuzz(f))

	// Seed corpus with examples of things the fuzzer can mutate.
	f.Add("v1:randomBase64Data")
	f.Add("v2:deadbeefdeadbeef:garbage")
	f.Add("shortString")
	f.Add("")
	f.Add("v1:")
	f.Add("v2:")
	f.Add("v2::no-id")
	f.Add("v1:valid-prefix-but-invalid-data-that-could-panic")

	f.Fuzz(func(t *testing.T, input string) {
		// The sole goal of this fuzz test is to ensure Decrypt never panics
		// on malformed, massive, or nil-like strings across all three
		// supported format branches.
		_, _ = svc.Decrypt(input)
	})
}

// randomHexKeyFuzz is the fuzzer-scoped variant of randomHexKey. Fuzz
// harnesses get *testing.F, not *testing.T, so we duplicate to avoid
// threading a dual-typed helper across both test bodies.
func randomHexKeyFuzz(f *testing.F) string {
	f.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(f, err)
	return hex.EncodeToString(raw)
}
