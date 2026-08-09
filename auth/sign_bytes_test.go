package auth

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignBytes_VerifyRoundTrip pins the §8 row-signing happy path: a
// signature produced by SignBytes verifies under VerifyBytes for the same
// payload, and the kid returned by SignBytes selects the right key for
// verification. Covers both EdDSA and ES256 primary keys.
func TestSignBytes_VerifyRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		key  domain.SigningKey
	}{
		{"eddsa", generateTestEdDSAKey()},
		{"es256", generateTestES256Key()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			km, err := NewKeyManager([]domain.SigningKey{c.key})
			require.NoError(t, err)

			payload := []byte("audit-chain-head:0xDEADBEEF")
			sig, kid, err := km.SignBytes(payload)
			require.NoError(t, err)
			require.NotEmpty(t, sig)
			require.Equal(t, c.key.KID, kid)

			require.NoError(t, km.VerifyBytes(payload, sig, kid),
				"signature produced by SignBytes must verify under VerifyBytes for the same payload + kid")
		})
	}
}

// TestSignBytes_TamperedPayloadDetected pins the load-bearing byzantine-
// fault property: a verifier handed a signature plus a different payload
// must reject. This is the entire point of row-signing — an attacker who
// mutates head_hash without re-signing leaves a signature pointing at the
// old hash.
func TestSignBytes_TamperedPayloadDetected(t *testing.T) {
	km, err := NewKeyManager([]domain.SigningKey{generateTestEdDSAKey()})
	require.NoError(t, err)

	original := []byte("original-head-hash")
	tampered := []byte("tampered-head-hash")
	sig, kid, err := km.SignBytes(original)
	require.NoError(t, err)

	err = km.VerifyBytes(tampered, sig, kid)
	require.Error(t, err, "verifier MUST reject when payload differs from what was signed")
}

// TestVerifyBytes_UnknownKID covers the rotation case: a kid the verifier
// has never loaded must surface as an error rather than silently
// pass-through. Identuum's KeyManager loads active + rotating keys, so a
// kid that was retired AND purged would land here. (For rotation in the
// other direction — a rotating key still loaded — verification succeeds.)
func TestVerifyBytes_UnknownKID(t *testing.T) {
	km, err := NewKeyManager([]domain.SigningKey{generateTestEdDSAKey()})
	require.NoError(t, err)
	err = km.VerifyBytes([]byte("payload"), []byte("sig"), "kid-that-does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown kid")
}

// TestSignBytes_NoPrimaryKey covers the boot-time-misconfiguration path:
// a KeyManager constructed without an active key (which the constructor
// already refuses) cannot reach SignBytes. We pin SignBytes' own nil-
// primary guard separately by zeroing the primary directly — defence in
// depth against a future Reload that could leave the manager in an
// inconsistent state.
func TestSignBytes_NoPrimaryKey(t *testing.T) {
	km, err := NewKeyManager([]domain.SigningKey{generateTestEdDSAKey()})
	require.NoError(t, err)

	// Force the no-primary state to exercise SignBytes' guard.
	km.mu.Lock()
	km.primaryKey = nil
	km.mu.Unlock()

	_, _, err = km.SignBytes([]byte("payload"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no primary key")
}
