package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// R4 — RFC 7009 §2.1 client-binding gate on POST /api/v1/oauth/revoke.
// Scenario (b) (cross-client refresh → silent no-op, token stays valid) is
// covered by TestRevocation_RefreshTokenCrossClientSilentNoOpTokenStaysValid
// in revocation_test.go. This file covers (a), (c), (d), (e). The harness
// (newRevocationEngine[WithRefresh], stubClientAuth, revFakeVerifier,
// newInMemoryRefreshRepoHandlers) lives in revocation_test.go.

func postRevoke(t *testing.T, r *gin.Engine, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// (a) owning client revokes its own refresh token → revoked (works).
func TestRevocationR4_OwningClientRevokesOwnRefreshToken(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	r, _, _, svc := newRevocationEngineWithRefresh(t, &revFakeVerifier{}, refreshRepo)
	issued, _ := svc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-own", Subject: "cli-own", AccessJTI: "jti-own",
	})
	w := postRevoke(t, r, "token="+issued.Token+"&token_type_hint=refresh_token&client_id=cli-own&client_secret=S")
	t.Logf("EVIDENCE (a) owning client refresh revoke: status=%d", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if row := refreshRepo.byID[issued.ID]; row == nil || row.RevokedAt == nil {
		t.Errorf("owning client revoke did not revoke the row: %+v", row)
	}
}

// (c) a client holding a victim's access token cannot fan out the victim's
// other sessions; the owning client can (control).
func TestRevocationR4_AccessTokenCrossClientNoSessionFanout(t *testing.T) {
	victim := uuid.New()
	claims := &service.IntrospectionClaims{Sub: victim.String(), UserID: victim, ClientID: "cli-ISSUER"}

	// Non-owning holder → NO fan-out.
	revHolder := &service.RecorderSessionRevoker{}
	rH, _ := newRevocationEngine(t, &revFakeVerifier{claims: claims}, revHolder, stubClientAuth{})
	postRevoke(t, rH, "token=victim-access&client_id=cli-HOLDER&client_secret=S")
	t.Logf("EVIDENCE (c) cross-client access revoke: fanoutCalls=%d (want 0)", len(revHolder.Calls()))
	if len(revHolder.Calls()) != 0 {
		t.Errorf("cross-client holder fanned out victim sessions: %+v", revHolder.Calls())
	}

	// Control: owning client → fan-out fires.
	revOwner := &service.RecorderSessionRevoker{}
	rO, _ := newRevocationEngine(t, &revFakeVerifier{claims: claims}, revOwner, stubClientAuth{})
	postRevoke(t, rO, "token=victim-access&client_id=cli-ISSUER&client_secret=S")
	t.Logf("EVIDENCE (c) owning client access revoke: fanoutCalls=%d (want 1)", len(revOwner.Calls()))
	if len(revOwner.Calls()) != 1 {
		t.Errorf("owning client did not fan out: calls=%d", len(revOwner.Calls()))
	}
}

// (e) binding-indeterminate (token carries no client_id) under an
// authenticated OAuth client → fail-closed, NO fan-out.
func TestRevocationR4_IndeterminateTokenClientFailsClosed(t *testing.T) {
	victim := uuid.New()
	rev := &service.RecorderSessionRevoker{}
	r, _ := newRevocationEngine(t, &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: victim.String(), UserID: victim, // NO ClientID
	}}, rev, stubClientAuth{})
	postRevoke(t, r, "token=victim-access&client_id=cli-ANY&client_secret=S")
	t.Logf("EVIDENCE (e) indeterminate token client: fanoutCalls=%d (want 0)", len(rev.Calls()))
	if len(rev.Calls()) != 0 {
		t.Errorf("fail-closed violated: fanned out on indeterminate token client: %+v", rev.Calls())
	}
}

// (d) site_admin fallback path (ClientAuth nil ⇒ RequireSiteAdmin; no OAuth
// client in context) still revokes broadly — the binding gate does NOT apply
// to the site_admin authority path, even for a token owned by another client.
func TestRevocationR4_SiteAdminFallbackRevokesBroadly(t *testing.T) {
	victim := uuid.New()
	rev := &service.RecorderSessionRevoker{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}))
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{claims: &service.IntrospectionClaims{
			Sub: victim.String(), UserID: victim, ClientID: "cli-SOME-OTHER",
		}}, nil),
		SessionRevoker: rev,
		ClientAuth:     nil, // ⇒ RequireSiteAdmin fallback (no OAuth client)
		Audit:          &audit.Recorder{},
	})
	w := postRevoke(t, r, "token=victim-access")
	t.Logf("EVIDENCE (d) site_admin fallback: status=%d fanoutCalls=%d (want 1)", w.Code, len(rev.Calls()))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if len(rev.Calls()) != 1 {
		t.Fatalf("site_admin broad revoke regressed: calls=%d, want 1", len(rev.Calls()))
	}
	if rev.Calls()[0].UserID != victim {
		t.Errorf("site_admin revoked wrong user: %s", rev.Calls()[0].UserID)
	}
}
