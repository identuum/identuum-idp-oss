package service

// webauthn_step_up.go — THE-PHISHING-RESISTANT-ACR: the seam the passkey
// step-up ceremony consumes. BeginAssertion is BeginLogin with the
// go-webauthn option type erased to `any` (JSON-marshalable
// PublicKeyCredentialRequestOptions), so the handlers layer — which may not
// import go-webauthn (boundaries.json) — can declare an interface over it
// and tests can fake it. Nothing about the ceremony itself changes: the same
// single-use ceremony session, the same validator, the same FinishLogin.

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// BeginAssertion starts a WebAuthn assertion ceremony for an ALREADY KNOWN
// user (the browser session's user) and returns the request options the
// page passes to navigator.credentials.get plus the single-use ceremony
// session id. ErrWebAuthnNoCredentials when the user has no passkey.
func (s *WebAuthnService) BeginAssertion(ctx context.Context, user *domain.User) (options any, sessionID string, err error) {
	assertion, sessionID, err := s.BeginLogin(ctx, user)
	if err != nil {
		return nil, "", err
	}
	return assertion.Response, sessionID, nil
}
