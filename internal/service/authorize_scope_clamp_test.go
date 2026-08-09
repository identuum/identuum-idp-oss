package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// R6 — AuthorizeService.Authorize clamps the requested scope to the client's
// registered scope set (RFC 6749 §3.3). These tests mint the code directly
// (SkipConsent=true) and read the persisted code's Scope, which is exactly
// what the token endpoint echoes as the response scope and what drives
// openid→id_token / offline_access→refresh.

func newScopeClampHarness(t *testing.T, clientScope string) (*AuthorizeService, *inMemoryAuthCodeRepo, *domain.Principal) {
	t.Helper()
	repo := newAuthCodeRepo()
	codes := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{client: &domain.Client{
		ClientID:     "cli-1",
		Name:         "Test client",
		RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent:  true, // bypass the consent gate so the code is minted
		Scope:        clientScope,
	}}
	sid := uuid.New()
	sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
		ID: sid, IsValid: true, CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}}
	svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithSessionLookup(sess)
	return svc, repo, authorizePrincipal(sid)
}

func mintedCodeScope(t *testing.T, repo *inMemoryAuthCodeRepo) string {
	t.Helper()
	for _, row := range repo.byID {
		return row.Scope
	}
	t.Fatalf("no authorization code was minted")
	return ""
}

func runAuthorizeWithScopes(t *testing.T, clientScope, requestedScope string) string {
	t.Helper()
	svc, repo, principal := newScopeClampHarness(t, clientScope)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.Scope = requestedScope
	if _, err := svc.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	return mintedCodeScope(t, repo)
}

// (a) a client requests only scopes it is registered for → all pass through.
func TestAuthorizeClamp_RegisteredScopesPassThrough(t *testing.T) {
	got := runAuthorizeWithScopes(t, "openid profile email", "openid profile")
	t.Logf("EVIDENCE (a) registered subset: client=[openid profile email] req=[openid profile] minted=%q", got)
	if got != "openid profile" {
		t.Fatalf("minted scope = %q, want \"openid profile\" (happy path unchanged)", got)
	}
}

// (b) a client requests a superset → unregistered scopes are dropped; only the
// intersection is granted/persisted and reflected in the (code→)token scope.
func TestAuthorizeClamp_SupersetIsNarrowedToIntersection(t *testing.T) {
	got := runAuthorizeWithScopes(t, "openid profile", "openid profile email admin")
	t.Logf("EVIDENCE (b) superset: client=[openid profile] req=[openid profile email admin] minted=%q", got)
	if got != "openid profile" {
		t.Fatalf("minted scope = %q, want \"openid profile\" (email, admin dropped)", got)
	}
}

// (c) a client requests openid/offline_access it is NOT registered for → those
// are dropped (so no id_token from openid, no refresh from offline_access).
func TestAuthorizeClamp_UnregisteredOpenidOfflineAccessDropped(t *testing.T) {
	got := runAuthorizeWithScopes(t, "profile", "openid profile offline_access")
	t.Logf("EVIDENCE (c) special scopes: client=[profile] req=[openid profile offline_access] minted=%q", got)
	if got != "profile" {
		t.Fatalf("minted scope = %q, want \"profile\" (openid + offline_access dropped)", got)
	}
}

// Unit: the clamp intersect + the empty-registered pass-through disposition.
func TestClampScopeToRegistered(t *testing.T) {
	cases := []struct {
		name, requested, registered, want string
	}{
		{"subset passes", "openid profile", "openid profile email", "openid profile"},
		{"superset narrowed", "openid profile email admin", "openid profile", "openid profile"},
		{"special dropped", "openid profile offline_access", "profile", "profile"},
		{"order follows requested", "profile openid", "openid profile", "profile openid"},
		{"empty registered ⇒ pass-through (unrestricted)", "openid profile", "", "openid profile"},
		{"empty requested ⇒ empty", "", "openid profile", ""},
		{"disjoint ⇒ empty", "admin billing", "openid profile", ""},
	}
	for _, tc := range cases {
		if got := ClampScopeToRegistered(tc.requested, tc.registered); got != tc.want {
			t.Errorf("%s: ClampScopeToRegistered(%q,%q)=%q, want %q", tc.name, tc.requested, tc.registered, got, tc.want)
		}
	}
	t.Logf("EVIDENCE (clamp helper) intersect + empty-registered pass-through verified")
}
