package service

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The step-up to the phishing-resistant rung asks the authenticator to verify
// the user (UserVerification "required"); an ordinary passkey sign-in keeps
// asking "preferred", so a key without a PIN can still sign in where the
// organization does not require MFA.
func TestBeginAssertion_AsksForUserVerificationRequired(t *testing.T) {
	f := newWebAuthnFixture(t)
	seedCredential(t, f, []byte{0x01})
	var asked protocol.UserVerificationRequirement
	f.validator.beginLogin = func(_ webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		var o protocol.PublicKeyCredentialRequestOptions
		for _, opt := range opts {
			opt(&o)
		}
		asked = o.UserVerification
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{Challenge: "c", UserID: f.user.ID[:]}, nil
	}

	_, _, err := f.svc.BeginAssertion(context.Background(), f.user)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, asked, "step-up must require user verification")

	_, _, err = f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationPreferred, asked, "an ordinary sign-in keeps asking preferred")
}
