package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeIntrospector returns canned IntrospectionClaims or an error
// so the service tests can pin every behavior without a JWT
// library / signing keys / claim parsing.
type fakeIntrospector struct {
	claims *IntrospectionClaims
	err    error
	calls  []string
}

func (f *fakeIntrospector) IntrospectToken(_ context.Context, raw string) (*IntrospectionClaims, error) {
	f.calls = append(f.calls, raw)
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// ---------- Construction ----------

func TestIntrospectionService_NewRequiresVerifier(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewIntrospectionService(nil, nil) did not panic")
		}
	}()
	_ = NewIntrospectionService(nil, nil, nil)
}

// ---------- active=false branches ----------

func TestIntrospect_EmptyTokenReturnsInactive(t *testing.T) {
	svc := NewIntrospectionService(nil, &fakeIntrospector{}, nil)
	resp := svc.Introspect(context.Background(), "")
	if resp.Active {
		t.Errorf("empty token = active:true; want false")
	}
}

func TestIntrospect_WhitespaceTokenReturnsInactive(t *testing.T) {
	svc := NewIntrospectionService(nil, &fakeIntrospector{}, nil)
	resp := svc.Introspect(context.Background(), "   \t  \n  ")
	if resp.Active {
		t.Errorf("whitespace token = active:true; want false")
	}
}

func TestIntrospect_VerifierErrorReturnsInactive(t *testing.T) {
	v := &fakeIntrospector{err: errors.New("any-failure-mode")}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "INVALID-TOKEN-MUST-NOT-LEAK")
	if resp.Active {
		t.Errorf("verifier error = active:true; want false")
	}
	if strings.Contains(resp.Sub+resp.Scope+resp.ClientID+resp.Username, "INVALID-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token sentinel")
	}
}

func TestIntrospect_NilClaimsReturnsInactive(t *testing.T) {
	svc := NewIntrospectionService(nil, &fakeIntrospector{claims: nil}, nil)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Active {
		t.Errorf("nil claims = active:true; want false")
	}
}

// A "verified" token whose claims have NO subject identifier at
// all is treated as inactive — a misconfigured claim set must not
// poison downstream authorization.
func TestIntrospect_NoSubjectReturnsInactive(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{Scope: "x"}}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Active {
		t.Errorf("no-subject = active:true; want false")
	}
}

// ---------- active=true happy path ----------

func TestIntrospect_ValidTokenSubFromSub(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub:      uid.String(),
		UserID:   uid,
		ClientID: "client-1",
		Email:    "u@example.test",
		Scope:    "openid users:read",
		Iss:      "https://idp.test",
		Aud:      []string{"https://api.example.test"},
		Exp:      1700000000,
		Iat:      1699999000,
		Nbf:      1699999000,
		Jti:      "jti-1",
	}}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "VALID-SIG-TOKEN-MUST-NOT-LEAK")
	if !resp.Active {
		t.Fatalf("valid token = active:false")
	}
	if resp.Sub != uid.String() {
		t.Errorf("sub = %q, want %q", resp.Sub, uid.String())
	}
	if resp.ClientID != "client-1" {
		t.Errorf("client_id = %q", resp.ClientID)
	}
	if resp.Username != "u@example.test" {
		t.Errorf("username = %q (want email projection)", resp.Username)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if resp.Iss != "https://idp.test" {
		t.Errorf("iss = %q", resp.Iss)
	}
	if len(resp.Aud) != 1 || resp.Aud[0] != "https://api.example.test" {
		t.Errorf("aud = %v", resp.Aud)
	}
	if resp.Exp != 1700000000 || resp.Iat != 1699999000 || resp.Nbf != 1699999000 {
		t.Errorf("exp/iat/nbf = %d/%d/%d", resp.Exp, resp.Iat, resp.Nbf)
	}
	if resp.Jti != "jti-1" {
		t.Errorf("jti = %q", resp.Jti)
	}
	// Safety: the raw token sentinel must NOT appear anywhere in
	// the response, including the scope string.
	for _, s := range []string{resp.Sub, resp.Scope, resp.ClientID, resp.Username, resp.Iss, resp.Jti} {
		if strings.Contains(s, "VALID-SIG-TOKEN-MUST-NOT-LEAK") {
			t.Errorf("response leaked raw token sentinel in %q", s)
		}
	}
}

// Sub is empty in claims but UserID is set — service synthesizes
// sub from UserID.
func TestIntrospect_SubFromUserIDWhenSubEmpty(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		UserID: uid, ClientID: "c",
	}}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Fatalf("active = false")
	}
	if resp.Sub != uid.String() {
		t.Errorf("sub synthesized = %q, want %q", resp.Sub, uid.String())
	}
}

// ---------- Scope override via UserScopeService ----------

func newUserScopeSvcWith(t *testing.T, scopes []string) *UserScopeService {
	t.Helper()
	repo := newUserScopeRepo()
	repo.out = scopes
	return NewUserScopeService(nil, repo)
}

func TestIntrospect_ScopeOverriddenByUserScopeService(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Scope: "openid stale:scope",
	}}
	scopeSvc := newUserScopeSvcWith(t, []string{"users:read", "billing:read"})
	svc := NewIntrospectionService(nil, v, scopeSvc)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Fatalf("active = false")
	}
	// UserScopeService dedupes + sorts.
	if resp.Scope != "billing:read users:read" {
		t.Errorf("scope override = %q, want sorted live scopes", resp.Scope)
	}
}

func TestIntrospect_ScopeRepoErrorFallsBackToClaim(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Scope: "openid users:read",
	}}
	repo := newUserScopeRepo()
	repo.err = errors.New("repo down")
	scopeSvc := NewUserScopeService(nil, repo)
	svc := NewIntrospectionService(nil, v, scopeSvc)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Fatalf("active = false")
	}
	// Fallback: token's own scope claim.
	if resp.Scope != "openid users:read" {
		t.Errorf("scope fallback = %q, want token claim", resp.Scope)
	}
}

func TestIntrospect_NoUserScopeServiceUsesClaimScope(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Scope: "openid users:read",
	}}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Scope != "openid users:read" {
		t.Errorf("scope = %q, want token claim verbatim", resp.Scope)
	}
}

// Empty effective scope list via UserScopeService — service still
// active:true with empty scope (omitempty drops it on the wire).
func TestIntrospect_EmptyEffectiveScopeStaysActive(t *testing.T) {
	uid := uuid.New()
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Scope: "openid",
	}}
	scopeSvc := newUserScopeSvcWith(t, nil)
	svc := NewIntrospectionService(nil, v, scopeSvc)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Fatalf("active = false on empty effective scope")
	}
	if resp.Scope != "" {
		t.Errorf("scope = %q, want empty (live RBAC bindings empty)", resp.Scope)
	}
}

// Claims with no UserID skip the UserScopeService entirely.
func TestIntrospect_NoUserIDSkipsScopeService(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "client-token", ClientID: "client-1", Scope: "openid",
	}}
	scopeSvc := newUserScopeSvcWith(t, []string{"never:read"})
	svc := NewIntrospectionService(nil, v, scopeSvc)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Scope != "openid" {
		t.Errorf("scope = %q, want claim verbatim when UserID=nil", resp.Scope)
	}
}

// ---------- Revocation checker integration ----------

// fakeRevocationChecker satisfies TokenRevocationChecker for tests.
type fakeRevocationChecker struct {
	revoked map[string]bool
	err     error
	calls   []string
}

func (f *fakeRevocationChecker) IsRevoked(_ context.Context, jti string) (bool, error) {
	f.calls = append(f.calls, jti)
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[jti], nil
}

func TestIntrospect_RevokedJTIReturnsInactive(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-1", Scope: "openid",
	}}
	rc := &fakeRevocationChecker{revoked: map[string]bool{"jti-1": true}}
	svc := NewIntrospectionService(nil, v, nil).WithRevocationChecker(rc)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Active {
		t.Errorf("revoked jti returned active:true")
	}
	if len(rc.calls) != 1 || rc.calls[0] != "jti-1" {
		t.Errorf("checker calls = %v", rc.calls)
	}
}

func TestIntrospect_NonRevokedJTIPassesThrough(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-good", Scope: "openid",
	}}
	rc := &fakeRevocationChecker{revoked: map[string]bool{"jti-other": true}}
	svc := NewIntrospectionService(nil, v, nil).WithRevocationChecker(rc)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Errorf("non-revoked jti returned active:false")
	}
}

func TestIntrospect_RevocationCheckerErrorIsFailClosed(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-x",
	}}
	rc := &fakeRevocationChecker{err: errors.New("revocation store down")}
	svc := NewIntrospectionService(nil, v, nil).WithRevocationChecker(rc)
	resp := svc.Introspect(context.Background(), "ANY")
	if resp.Active {
		t.Errorf("revocation-checker error must flip active:false (fail closed)")
	}
}

func TestIntrospect_NoJTIClaimSkipsRevocationCheck(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1",
	}}
	rc := &fakeRevocationChecker{}
	svc := NewIntrospectionService(nil, v, nil).WithRevocationChecker(rc)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Errorf("no jti and no revocation hit but active:false")
	}
	if len(rc.calls) != 0 {
		t.Errorf("checker called for claim with no jti: %v", rc.calls)
	}
}

func TestIntrospect_NoCheckerWiredIgnoresRevocation(t *testing.T) {
	v := &fakeIntrospector{claims: &IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-doesnt-matter",
	}}
	svc := NewIntrospectionService(nil, v, nil)
	resp := svc.Introspect(context.Background(), "ANY")
	if !resp.Active {
		t.Errorf("no revocation checker but active:false")
	}
}
