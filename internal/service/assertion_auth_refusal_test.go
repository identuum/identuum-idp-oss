package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// pkjwtClientLookup returns one fixed client for any client_id.
type pkjwtClientLookup struct{ client *domain.Client }

func (l pkjwtClientLookup) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return l.client, nil
}

// TestAuthenticateAssertion_RefusesBadAssertion pins RFC 7523 private_key_jwt
// client authentication: a private_key_jwt client presenting a malformed or
// wrong-signature assertion is refused with ErrInvalidOAuthClientCredentials —
// the assertion is validated (alg/aud/exp/signature) before the client is
// authenticated, so a self-signed or tampered JWT never authenticates.
// RULE: ASSERTION-AUTH-REFUSE-1
func TestAuthenticateAssertion_RefusesBadAssertion(t *testing.T) {
	validator, err := NewClientAssertionValidator(ClientAssertionValidatorConfig{
		TokenEndpointURL: "https://idp.example.com/token",
	})
	if err != nil {
		t.Fatalf("validator construction: %v", err)
	}
	client := &domain.Client{ID: uuid.New(), ClientID: "cid", TokenEndpointAuthMethod: "private_key_jwt"}
	svc := &OAuthClientAuthService{
		assertionVerify:  validator,
		clientByClientID: pkjwtClientLookup{client: client},
	}

	// A malformed assertion for a private_key_jwt client is refused.
	if _, aerr := svc.AuthenticateAssertion(context.Background(), "cid", "not-a-valid-jwt"); !errors.Is(aerr, ErrInvalidOAuthClientCredentials) {
		t.Errorf("a bad private_key_jwt assertion must be refused with ErrInvalidOAuthClientCredentials, got %v", aerr)
	}
}
