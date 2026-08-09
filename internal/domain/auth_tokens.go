package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuthTokens represents the set of tokens returned upon successful authentication.
// This decouples the service layer from the API DTOs (types.TokenResponse).
type AuthTokens struct {
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	AccessToken      string
	RefreshToken     string
	TokenType        string
	IDToken          string
	ExpiresIn        int
	RefreshExpiresIn int
}

// SecureRefreshToken represents a secure refresh token with selector/validator split
// This prevents database compromise from leading to immediate token reuse
type SecureRefreshToken struct {
	Validator []byte
	Selector  uuid.UUID
}

// Encode creates the client-facing token string as selector.validator_base64
func (srt *SecureRefreshToken) Encode() string {
	validatorB64 := base64.URLEncoding.EncodeToString(srt.Validator)
	return srt.Selector.String() + "." + validatorB64
}

// ParseSecureRefreshToken parses a client token string into selector and validator
func ParseSecureRefreshToken(token string) (*SecureRefreshToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format: expected selector.validator")
	}

	selector, err := uuid.Parse(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid selector: %w", err)
	}

	validator, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid validator: %w", err)
	}

	return &SecureRefreshToken{
		Selector:  selector,
		Validator: validator,
	}, nil
}
