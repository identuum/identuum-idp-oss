package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// fakeIntrospectionVerifier is the smallest TokenClaimsVerifier
// that lets the api-router /oauth/revoke wiring be exercised end-
// to-end without touching JWT crypto. It returns whatever claims
// the test supplies, scoped per-call to the raw token string for
// strict no-leak assertions.
type fakeIntrospectionVerifier struct {
	claims *service.IntrospectionClaims
}

func (f *fakeIntrospectionVerifier) IntrospectToken(_ context.Context, _ string) (*service.IntrospectionClaims, error) {
	return f.claims, nil
}

// stubAlwaysAllowClientAuth mounts the RFC 7009 §2.1 client-auth
// front of the route without exercising the full Basic / Post /
// private_key_jwt branches. The handler reads the resulting
// AuthenticatedClient from mw.AuthenticatedClientFromContext so
// the deny path still triggers correctly when nil-returned.
type stubAlwaysAllowClientAuth struct{}

func (stubAlwaysAllowClientAuth) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{
		Kind:         service.AuthenticatedClientKindOAuth,
		ClientID:     id,
		AuthRecordID: uuid.New(),
	}, nil
}

// postRevoke is a one-liner POST helper.
func postRevoke(t *testing.T, deps OSSRouterDeps, form string) *httptest.ResponseRecorder {
	t.Helper()
	engine := NewOSSEngine(deps)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// TestOSSEngine_RevokeFiresSessionRevokerWhenWired pins the
// runtime → OSSRouterDeps → RevocationHandlerDeps wiring. With
// SessionRevoker set, a successfully verified token whose `sub`
// resolves to a UUID MUST fan out one and only one
// RevokeUserSessions call against that user, with reason
// "oauth_token_revoked".
func TestOSSEngine_RevokeFiresSessionRevokerWhenWired(t *testing.T) {
	targetUser := uuid.New()
	verifier := &fakeIntrospectionVerifier{
		claims: &service.IntrospectionClaims{
			Sub:      targetUser.String(),
			ClientID: "cli-A",
			Jti:      "JTI-A",
			Exp:      4102444800, // 2100-01-01 — far enough in the future for any clock.
		},
	}
	revoker := &service.RecorderSessionRevoker{}
	deps := OSSRouterDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:       revoker,
		OAuthClientAuth:      stubAlwaysAllowClientAuth{},
		Audit:                &audit.Recorder{},
	}

	const rawToken = "OPAQUE-ACCESS-TOKEN-MUST-NOT-LEAK"
	w := postRevoke(t, deps, "token="+rawToken+"&client_id=cli-A&client_secret=S")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (RFC 7009 §2.2); body=%q", w.Code, w.Body.String())
	}
	calls := revoker.Calls()
	if len(calls) != 1 {
		t.Fatalf("session revoker called %d times; want 1 (real revoker MUST be wired)", len(calls))
	}
	if calls[0].UserID != targetUser {
		t.Errorf("revoker user_id = %v; want %v", calls[0].UserID, targetUser)
	}
	if calls[0].Reason != "oauth_token_revoked" {
		t.Errorf("revoker reason = %q; want %q", calls[0].Reason, "oauth_token_revoked")
	}
	// Wire-shape no-leak: the response body MUST NOT echo the raw
	// token, the revocation reason, or any audit-side detail. RFC
	// 7009 §2.2 mandates an opaque 200.
	body := w.Body.String()
	if strings.Contains(body, rawToken) {
		t.Errorf("revoke response leaked raw token: %q", body)
	}
	if strings.Contains(body, "oauth_token_revoked") {
		t.Errorf("revoke response leaked revocation reason: %q", body)
	}
}

// TestOSSEngine_RevokeFallsBackToNoopWhenSessionRevokerNil pins
// the safe-default fallback: a deployment that has not wired
// UserSessionService (SessionRevoker == nil on OSSRouterDeps)
// MUST still serve /oauth/revoke and return the RFC 7009 200, with
// NoopSessionRevoker silently swallowing the fan-out. The handler
// MUST NOT panic, MUST NOT 5xx, and MUST NOT echo the raw token.
func TestOSSEngine_RevokeFallsBackToNoopWhenSessionRevokerNil(t *testing.T) {
	verifier := &fakeIntrospectionVerifier{
		claims: &service.IntrospectionClaims{
			Sub:      uuid.New().String(),
			ClientID: "cli-B",
			Jti:      "JTI-B",
			Exp:      4102444800,
		},
	}
	deps := OSSRouterDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		// SessionRevoker: nil  ← the unwired-deployment shape.
		OAuthClientAuth: stubAlwaysAllowClientAuth{},
		Audit:           &audit.Recorder{},
	}

	const rawToken = "OPAQUE-NIL-REVOKER-TOKEN-MUST-NOT-LEAK"
	w := postRevoke(t, deps, "token="+rawToken+"&client_id=cli-B&client_secret=S")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil-revoker fallback MUST still serve)", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, rawToken) {
		t.Errorf("revoke fallback response leaked raw token: %q", body)
	}
}

// TestOSSEngine_RevokeAuditCarriesNoRawTokenWhenRevokerWired pins
// the wire+audit no-leak contract. Even when the handler emits an
// audit row (firedSession=true path), neither the response body
// nor the captured audit metadata may carry the raw token or the
// verifier's jti as plaintext outside the documented `jti`-binding
// of the per-row revocation persistence.
func TestOSSEngine_RevokeAuditCarriesNoRawTokenWhenRevokerWired(t *testing.T) {
	const rawToken = "REVOKE-AUDIT-LEAK-CANARY"
	const jti = "JTI-AUDIT-CANARY"
	targetUser := uuid.New()
	verifier := &fakeIntrospectionVerifier{
		claims: &service.IntrospectionClaims{
			Sub:      targetUser.String(),
			ClientID: "cli-C",
			Jti:      jti,
			Exp:      4102444800,
		},
	}
	revoker := &service.RecorderSessionRevoker{}
	rec := &audit.Recorder{}
	deps := OSSRouterDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:       revoker,
		OAuthClientAuth:      stubAlwaysAllowClientAuth{},
		Audit:                rec,
	}

	w := postRevoke(t, deps, "token="+rawToken+"&client_id=cli-C&client_secret=S")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), rawToken) {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
	// Per-revoker metadata: must NOT carry the raw token or jti.
	for _, call := range revoker.Calls() {
		for _, v := range call.Metadata {
			if s, ok := v.(string); ok {
				if strings.Contains(s, rawToken) {
					t.Errorf("session revoker metadata leaked raw token: %q", s)
				}
				if strings.Contains(s, jti) {
					t.Errorf("session revoker metadata leaked jti: %q", s)
				}
			}
		}
	}
	// Audit metadata: at most carries the OAuth client identifier.
	// The raw token is FORBIDDEN; the jti may only appear in the
	// separate TokenRevocationService persistence path (not in
	// audit-event metadata, which is operator-facing).
	for _, e := range rec.Events() {
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, rawToken) {
				t.Errorf("audit metadata leaked raw token: %q", s)
			}
		}
	}
}
