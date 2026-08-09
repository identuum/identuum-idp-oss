package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPurposeClaim_RoundTrip covers serialization + parsing of the new
// JWTClaims.Purpose field through the SignAccessToken → ValidateJWTToken
// path. The §13.7 invariant depends on this round-trip working — a
// dropped purpose claim would silently demote a consent session into
// a standard one.
func TestPurposeClaim_RoundTrip(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	in := domain.JWTClaims{
		UserID:    userID,
		Issuer:    "identuum",
		Subject:   userID.String(),
		Audience:  []string{"identuum-admin"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Purpose:   domain.SessionPurposeConsent,
	}

	tokenString, err := km.SignAccessToken(in)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	out, err := km.ValidateJWTToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, domain.SessionPurposeConsent, out.Purpose,
		"purpose claim must round-trip through sign+validate; got %q", out.Purpose)
	assert.True(t, domain.IsConsentPurposeSession(out))
}

// TestPurposeClaim_OmittedWhenEmpty asserts that a standard session
// (Purpose=="") does not emit the claim into the JWT payload — both as
// a wire-size optimisation and as a guarantee that historical tokens
// (which never had this field) still parse equivalently.
func TestPurposeClaim_OmittedWhenEmpty(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	in := domain.JWTClaims{
		UserID:    userID,
		Issuer:    "identuum",
		Subject:   userID.String(),
		Audience:  []string{"identuum-admin"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		// No Purpose set — standard session.
	}
	tokenString, err := km.SignAccessToken(in)
	require.NoError(t, err)

	out, err := km.ValidateJWTToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "", out.Purpose, "standard sessions must have empty purpose")
	assert.False(t, domain.IsConsentPurposeSession(out),
		"standard session must NOT register as consent-purpose")
}

func TestIsConsentPurposeSession_NilClaimsReturnsFalse(t *testing.T) {
	// Defence in depth: nil claims (no session at all) is NOT the same
	// as a consent-purpose session. The middleware separates these
	// concerns — auth handles "missing", purpose middleware handles
	// "narrowed scope".
	assert.False(t, domain.IsConsentPurposeSession(nil))
}

func TestIsConsentPurposeSession_OtherPurposesReturnFalse(t *testing.T) {
	// Future-proofing: other non-empty purpose values do NOT register
	// as consent. Only the exact "consent" string maps. (No other
	// purposes are defined today; this test pins the rule for when
	// they get added.)
	for _, p := range []string{"", "other", "Consent", "CONSENT", "consent_v2"} {
		c := &domain.JWTClaims{Purpose: p}
		got := domain.IsConsentPurposeSession(c)
		assert.False(t, got, "purpose=%q must NOT register as consent-purpose; got true", p)
	}
}
