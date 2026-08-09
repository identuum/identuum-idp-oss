package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// SignAccessToken signs a standard JWT token with the primary key.
//
// 4.4g.4a re-narrowing: agentic claim emission removed; the signer no longer
// stamps agentic AG fields onto the wire. AG token issuance lives in identuum-ag.
func (km *KeyManager) SignAccessToken(claims domain.JWTClaims) (string, error) {
	km.mu.RLock()
	key := km.primaryKey
	km.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("no active signing key available")
	}

	internalClaims := privateJWTClaims{
		UserID:         claims.UserID,
		Email:          claims.Email,
		OrganizationID: claims.OrganizationID,
		Role:           claims.Role,
		SessionID:      claims.SessionID,
		Type:           claims.Type,
		Kind:           claims.Kind,
		Scope:          claims.Scope,
		ClientID:       claims.ClientID,
		Purpose:        claims.Purpose,
		Acr:            claims.Acr,
		AuthTime:       claims.AuthTime,
		Act:            claims.Act,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   claims.Issuer,
			Subject:  claims.Subject,
			Audience: claims.Audience,
			ID:       claims.ID,
		},
	}
	if !claims.ExpiresAt.IsZero() {
		internalClaims.ExpiresAt = jwt.NewNumericDate(claims.ExpiresAt)
	}
	if claims.NotBefore != nil {
		internalClaims.NotBefore = jwt.NewNumericDate(*claims.NotBefore)
	}
	if !claims.IssuedAt.IsZero() {
		internalClaims.IssuedAt = jwt.NewNumericDate(claims.IssuedAt)
	}

	var token *jwt.Token
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, internalClaims)
	case domain.KeyAlgorithmES256:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, internalClaims)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}

	token.Header["kid"] = key.KID
	return token.SignedString(key.PrivateKey)
}
