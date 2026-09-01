package service

// authcode_reuse_chain_test.go — THE-CODE-REUSE-REVOKER: a replayed
// authorization code revokes what its FIRST exchange minted, through the
// EXISTING revocation paths, proved end-to-end inside the service layer with
// recording repositories:
//
//	exchange → record issued tokens → replay (refused) →
//	first access token REFUSED at introspection →
//	refresh token REFUSED at rotation.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type reuseChain struct {
	codes       *AuthorizationCodeService
	revocations *fakeRevocationRepo
	tokenRevoke *TokenRevocationService
	refresh     *RefreshTokenService
	code        string
	verifier    string
	accessJTI   string
	accessExp   time.Time
	refreshRaw  string
	refreshID   uuid.UUID
}

// newReuseChain mints a code, exchanges it once (Consume + RefreshTokenService.Issue),
// and records the minted access jti + refresh id on the code row — exactly
// what handleAuthorizationCodeGrant does — with the production revoker wired.
func newReuseChain(t *testing.T) *reuseChain {
	t.Helper()
	revocations := newFakeRevocationRepo()
	tokenRevoke := NewTokenRevocationService(nil, revocations)
	refresh := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{}).
		WithTokenRevocationService(tokenRevoke)
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour}).
		WithReuseRevoker(NewAuthCodeReuseRevocation(tokenRevoke, refresh))

	verifier, challenge := pkceVerifierAndChallenge(t)
	userID := uuid.New()
	created, err := codes.Create(context.Background(), CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: userID, SessionID: uuid.New(),
		RedirectURI: "https://app.example.com/cb", Scope: "openid offline_access",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	consumed, err := codes.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: created.Code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if consumed.ID != created.ID {
		t.Fatalf("Consume must return the row id the exchange records against: got %s want %s", consumed.ID, created.ID)
	}
	accessJTI := "access-jti-" + uuid.NewString()
	accessExp := time.Now().Add(time.Hour)
	issued, err := refresh.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: userID.String(), Scope: "openid offline_access", AccessJTI: accessJTI,
	})
	if err != nil {
		t.Fatalf("refresh Issue: %v", err)
	}
	rid := issued.ID
	if err := codes.RecordIssuedTokens(context.Background(), consumed.ID, accessJTI, accessExp, &rid); err != nil {
		t.Fatalf("RecordIssuedTokens: %v", err)
	}
	return &reuseChain{
		codes: codes, revocations: revocations, tokenRevoke: tokenRevoke, refresh: refresh,
		code: created.Code, verifier: verifier, accessJTI: accessJTI, accessExp: accessExp,
		refreshRaw: issued.Token, refreshID: issued.ID,
	}
}

func (c *reuseChain) introspectActive(t *testing.T) bool {
	t.Helper()
	uid := uuid.New()
	intro := NewIntrospectionService(nil, &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: uid.String(), UserID: uid, ClientID: "cli-1", Jti: c.accessJTI, Scope: "openid",
	}}, nil).WithRevocationChecker(c.tokenRevoke)
	return intro.Introspect(context.Background(), "ANY").Active
}

func (c *reuseChain) replay(t *testing.T) {
	t.Helper()
	_, err := c.codes.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: c.code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: c.verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Fatalf("replay must still be refused with invalid_grant, got %v", err)
	}
}

// RULE: CODE-REUSE-REVOKES-1
func TestAuthCodeReuse_RevokesFirstExchangeTokens(t *testing.T) {
	c := newReuseChain(t)

	// Controls BEFORE the replay: everything the first exchange minted works.
	if !c.introspectActive(t) {
		t.Fatalf("control: the first access token must be active before any replay")
	}
	if len(c.revocations.inserts) != 0 {
		t.Fatalf("control: a single exchange must revoke nothing (%d revocations)", len(c.revocations.inserts))
	}

	c.replay(t)

	// The first access token is REFUSED at introspection — through the same
	// oauth_token_revocations store the RFC 7009 endpoint writes.
	if c.introspectActive(t) {
		t.Fatalf("after replay the FIRST access token must be refused at introspection — it is still active")
	}
	// Exactly ONE distinct jti is revoked — the first exchange's access token.
	// It arrives twice by design (directly with the precise access expiry, and
	// again through the refresh family's linked-access cascade); the store's
	// insert is ON CONFLICT DO NOTHING, so the direct row — first in, with the
	// reuse reason — is the one that lands.
	if got := distinctRevokedJTIs(c.revocations); len(got) != 1 || got[0] != c.accessJTI {
		t.Fatalf("revocation store: want exactly the first access jti, got %v", got)
	}
	if got := c.revocations.inserts[0]; got.Jti != c.accessJTI || got.Reason != ReasonAuthorizationCodeReuse || !got.ExpiresAt.Equal(c.accessExp) {
		t.Errorf("first revocation row = %q reason %q exp %v, want the access jti / %q / the recorded access expiry %v", got.Jti, got.Reason, got.ExpiresAt, ReasonAuthorizationCodeReuse, c.accessExp)
	}

	// The refresh token minted from that code is REFUSED at rotation.
	if _, err := c.refresh.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: c.refreshRaw, ClientID: "cli-1"}); !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Fatalf("after replay the refresh token minted from the code must be refused at rotation, got %v", err)
	}
}

// A second replay is idempotent: nothing new to revoke, still refused.
func TestAuthCodeReuse_SecondReplayIsIdempotent(t *testing.T) {
	c := newReuseChain(t)
	c.replay(t)
	c.replay(t)
	if got := distinctRevokedJTIs(c.revocations); len(got) != 1 || got[0] != c.accessJTI {
		t.Fatalf("replaying twice must not revoke anything new: distinct jtis %v", got)
	}
	if c.introspectActive(t) {
		t.Fatalf("first access token must stay refused")
	}
}

// distinctRevokedJTIs mirrors the store's ON CONFLICT (jti) DO NOTHING view of
// the fake's append-only insert log.
func distinctRevokedJTIs(repo *fakeRevocationRepo) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range repo.inserts {
		if !seen[r.Jti] {
			seen[r.Jti] = true
			out = append(out, r.Jti)
		}
	}
	return out
}

// A code row that recorded nothing (legacy row, or an exchange that failed
// after consume) revokes nothing — there is nothing to revoke, and a garbage
// replay must not be able to force revocations.
func TestAuthCodeReuse_NothingRecordedRevokesNothing(t *testing.T) {
	revocations := newFakeRevocationRepo()
	tokenRevoke := NewTokenRevocationService(nil, revocations)
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour}).
		WithReuseRevoker(NewAuthCodeReuseRevocation(tokenRevoke, nil))
	verifier, challenge := pkceVerifierAndChallenge(t)
	created, _ := codes.Create(context.Background(), CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: uuid.New(), SessionID: uuid.New(),
		RedirectURI: "https://app.example.com/cb", Scope: "openid",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	in := ConsumeAuthorizationCodeInput{Code: created.Code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier}
	if _, err := codes.Consume(context.Background(), in); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := codes.Consume(context.Background(), in); !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Fatalf("replay err = %v", err)
	}
	if len(revocations.inserts) != 0 {
		t.Errorf("nothing recorded → nothing revoked, got %+v", revocations.inserts)
	}
}

func TestRecordIssuedTokens_RejectsIncompleteInput(t *testing.T) {
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
	if err := codes.RecordIssuedTokens(context.Background(), uuid.Nil, "jti", time.Now().Add(time.Hour), nil); !errors.Is(err, ErrAuthCodeInvalidInput) {
		t.Errorf("nil code id: err = %v", err)
	}
	if err := codes.RecordIssuedTokens(context.Background(), uuid.New(), "", time.Now().Add(time.Hour), nil); !errors.Is(err, ErrAuthCodeInvalidInput) {
		t.Errorf("empty jti: err = %v", err)
	}
	if err := codes.RecordIssuedTokens(context.Background(), uuid.New(), "jti", time.Time{}, nil); !errors.Is(err, ErrAuthCodeInvalidInput) {
		t.Errorf("zero expiry: err = %v", err)
	}
}
