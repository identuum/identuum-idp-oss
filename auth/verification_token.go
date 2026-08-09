package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// GenerateVerificationToken generates a token for email verification.
// issuer must be set to the deployment base URL (e.g. s.config.Get().BaseURL) so that
// ValidateVerificationToken can enforce same-deployment binding via the "iss" claim.
func (km *KeyManager) GenerateVerificationToken(userID uuid.UUID, email, issuer string) (string, error) {
	km.mu.RLock()
	key := km.primaryKey
	km.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("no active signing key available")
	}

	// Build claims directly — email is stored only in the custom "email" claim.
	// The "sub" claim carries the user ID; "aud" scopes the token purpose;
	// "iss" binds the token to this specific deployment.
	// "jti" is a per-call UUIDv7 so tokens generated for the same user at the
	// same instant (e.g. ResendVerificationEmail in rapid succession) produce
	// distinct hashes and can be individually revoked. v7 enforces the
	// service-wide UUID invariant — see internal/utils/uuidgen.
	jti, err := uuidgen.NewV7String()
	if err != nil {
		return "", fmt.Errorf("failed to generate verification token jti: %w", err)
	}
	now := time.Now()
	mapClaims := jwt.MapClaims{
		"exp":   jwt.NewNumericDate(now.Add(24 * time.Hour)),
		"iat":   jwt.NewNumericDate(now),
		"jti":   jti,
		"iss":   issuer,
		"sub":   userID.String(),
		"aud":   jwt.ClaimStrings{"verify-email"},
		"email": email,
	}

	var token *jwt.Token
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, mapClaims)
	case domain.KeyAlgorithmES256:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, mapClaims)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}

	token.Header["kid"] = key.KID
	return token.SignedString(key.PrivateKey)
}

// ValidateVerificationToken validates an email verification token.
// expectedIssuer must match the deployment base URL used when the token was generated.
func (km *KeyManager) ValidateVerificationToken(tokenString, expectedIssuer string) (uuid.UUID, string, error) {
	if tokenString == "" {
		return uuid.Nil, "", fmt.Errorf("%s", ErrMsgInvalidTokenFormat)
	}

	token, err := jwt.Parse(tokenString, km.standardKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return uuid.Nil, "", fmt.Errorf("%s", ErrMsgTokenExpired)
		}
		return uuid.Nil, "", fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	if !token.Valid {
		return uuid.Nil, "", fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, "", fmt.Errorf("invalid claims type")
	}

	// Verify Audience
	aud, err := claims.GetAudience()
	if err != nil || len(aud) == 0 || aud[0] != "verify-email" {
		return uuid.Nil, "", fmt.Errorf("invalid token purpose")
	}

	// Verify Issuer
	iss, issErr := claims.GetIssuer()
	if issErr != nil || iss != expectedIssuer {
		return uuid.Nil, "", fmt.Errorf("invalid token issuer")
	}

	// Extract UserID
	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return uuid.Nil, "", fmt.Errorf("invalid subject")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid user id format")
	}

	// Extract Email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return uuid.Nil, "", fmt.Errorf("invalid email in token")
	}

	return userID, email, nil
}

// ExtractUserIDFromExpiredVerificationToken parses a verification JWT
// for tenant-inference purposes ONLY. Verifies the signature and the
// audience/issuer claims, but tolerates expiry — returns (userID, nil)
// when the token is signature-valid but expired, so callers can map
// the user_id to an organization for tenant-scoped UX (e.g. the
// SSOMigrationProbe rendering the SSO-migration explanation page).
//
// MUST NOT be used to authorise any state mutation. The standard
// ValidateVerificationToken is the load-bearing safety primitive for
// consumption flows; this sibling exists exclusively for the rejected-
// token UX path where the answer is already "no, this token is bad,
// here's why we render this specific page" rather than "yes, do work
// on behalf of this user."
//
// Returns uuid.Nil when the signature fails, the issuer/audience
// don't match, or any claim is malformed — i.e. anything that would
// make tenant inference unsafe.
func (km *KeyManager) ExtractUserIDFromExpiredVerificationToken(tokenString, expectedIssuer string) uuid.UUID {
	if tokenString == "" {
		return uuid.Nil
	}
	// Use a parser that skips ONLY the time-based claim checks. The
	// signature, audience, and issuer checks below remain enforced —
	// signature-invalid or wrong-tenant tokens still resolve to Nil.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(tokenString, km.standardKeyFunc)
	if err != nil || token == nil || !token.Valid {
		// "valid" here means signature checked out (since claims
		// validation is suppressed); a signature-valid expired token
		// still has token.Valid == true under WithoutClaimsValidation.
		// A signature-INVALID token returns err != nil, hitting this
		// branch and returning Nil — exactly the right safety boundary.
		if err == nil {
			return uuid.Nil
		}
		// Signature errors are caught by the err != nil branch above.
		// jwt.ErrTokenExpired and friends never fire under
		// WithoutClaimsValidation, so reaching this point with a non-
		// nil err means a real signature/parse failure.
		return uuid.Nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil
	}
	aud, err := claims.GetAudience()
	if err != nil || len(aud) == 0 || aud[0] != "verify-email" {
		return uuid.Nil
	}
	iss, issErr := claims.GetIssuer()
	if issErr != nil || iss != expectedIssuer {
		return uuid.Nil
	}
	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return uuid.Nil
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil
	}
	return userID
}
