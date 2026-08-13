package service

// authcode_reuse_revocation_test.go — P0-1b: a replayed authorization code is
// evidence of compromise, so what the FIRST exchange minted is revoked.
//
// Owner ruling 2026-08-04, per RFC 6819 §5.2.1.1 and the OAuth 2.0 Security
// BCP. Rejecting the replay alone is necessary and NOT sufficient: whoever
// exchanged the code first still holds live tokens, and that is the party who
// may be the attacker.
//
// The accepted cost, ruled on rather than discovered: a client that
// double-submits one code revokes its own user's tokens.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// recordingRevoker captures what it was asked to revoke.
type recordingRevoker struct {
	calls []*domain.OAuthAuthorizationCode
	err   error
}

func (r *recordingRevoker) RevokeForReusedCode(_ context.Context, code *domain.OAuthAuthorizationCode, _ time.Time) error {
	r.calls = append(r.calls, code)
	return r.err
}

func newReuseFixture(t *testing.T) (*AuthorizationCodeService, *recordingRevoker, string) {
	t.Helper()
	repo := newAuthCodeRepo()
	rev := &recordingRevoker{}
	svc := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour}).
		WithReuseRevoker(rev)

	verifier, challenge := authorizeChallenge(t)
	created, err := svc.Create(context.Background(), CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	code := created.Code
	// First exchange succeeds and consumes the code.
	if _, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	}); err != nil {
		t.Fatalf("first Consume must succeed: %v", err)
	}
	if len(rev.calls) != 0 {
		t.Fatalf("a FIRST exchange must not revoke anything (%d calls)", len(rev.calls))
	}
	_ = verifier
	return svc, rev, code
}

// TestAuthCodeReuse_RevokesOnReplay is the P0-1b assertion.
// RULE: AUTHCODE-REPLAY-1
func TestAuthCodeReuse_RevokesOnReplay(t *testing.T) {
	svc, rev, code := newReuseFixture(t)
	verifier, _ := authorizeChallenge(t)

	// REPLAY the same code.
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	})
	if err != ErrAuthCodeInvalidGrant {
		t.Fatalf("replay err = %v, want ErrAuthCodeInvalidGrant", err)
	}
	if len(rev.calls) != 1 {
		t.Fatalf("a REPLAYED code must revoke what the first exchange minted; revoker calls = %d, want 1", len(rev.calls))
	}
	if rev.calls[0].ClientID != "cli-1" {
		t.Errorf("revoker got client %q, want cli-1 — it must receive the ORIGINAL code row", rev.calls[0].ClientID)
	}
	if rev.calls[0].ConsumedAt == nil {
		t.Error("the row handed to the revoker must be the CONSUMED one, so the caller can see when it was first used")
	}
}

// TestAuthCodeReuse_UnknownCodeDoesNotRevoke is the other half: a code that was
// never issued is an ordinary bad request, not evidence of compromise. Without
// this, "revoke on anything the active lookup rejects" would let an attacker
// force revocations by posting garbage.
func TestAuthCodeReuse_UnknownCodeDoesNotRevoke(t *testing.T) {
	svc, rev, _ := newReuseFixture(t)
	verifier, _ := authorizeChallenge(t)

	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: "a-code-that-was-never-issued", ClientID: "cli-1",
		RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	})
	if err != ErrAuthCodeInvalidGrant {
		t.Fatalf("unknown code err = %v, want ErrAuthCodeInvalidGrant", err)
	}
	if len(rev.calls) != 0 {
		t.Errorf("an UNKNOWN code must revoke nothing; revoker calls = %d", len(rev.calls))
	}
}

// TestAuthCodeReuse_NilRevokerPreservesBehaviour pins that leaving the seam
// unwired is exactly the pre-P0-1b behaviour — replay still rejected, nothing
// else touched — so wiring it is a deployment decision rather than a silent
// change for anyone who has not.
func TestAuthCodeReuse_NilRevokerPreservesBehaviour(t *testing.T) {
	repo := newAuthCodeRepo()
	svc := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	verifier, challenge := authorizeChallenge(t)
	created, err := svc.Create(context.Background(), CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: uuid.New(), SessionID: uuid.New(),
		RedirectURI: "https://app.example.com/cb", Scope: "openid",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	code := created.Code
	in := ConsumeAuthorizationCodeInput{
		Code: code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	}
	if _, err := svc.Consume(context.Background(), in); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := svc.Consume(context.Background(), in); err != ErrAuthCodeInvalidGrant {
		t.Fatalf("replay with no revoker wired: err = %v, want ErrAuthCodeInvalidGrant", err)
	}
}
