package handlers

// revocation_r8_test.go — R8: store I/O error masking.
//
// Before R8: a genuine store I/O error from RevokeJTI or RevokeByRawToken
// was silently swallowed and the handler returned 200.
// After R8:  a genuine store I/O error returns 500. RFC 7009 §2.2's
//            unconditional-200 rule continues to apply to invalid /
//            not-found / already-revoked tokens.
//
// Required proofs:
//   (d)  genuine store I/O error on RevokeJTI        → 500
//   (d2) genuine store I/O error on RevokeByRawToken → 500
//   (e)  invalid / not-found / already-expired token → 200 (RFC 7009 preserved)
//   (f)  R4 client-binding: cross-client refresh revoke still returns 200

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// errRevocationRepo always returns an I/O error from Insert so we can
// simulate a genuine store failure during RevokeJTI.
type errRevocationRepo struct{ insertErr error }

func (e *errRevocationRepo) Insert(_ context.Context, _ *domain.TokenRevocation) error {
	return e.insertErr
}
func (e *errRevocationRepo) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (e *errRevocationRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// errRefreshRepo always returns an I/O error from GetByID, simulating a
// store failure during RevokeByRawToken's selector lookup.
type errRefreshRepo struct{ getErr error }

func (e *errRefreshRepo) Insert(_ context.Context, _ *domain.RefreshToken) error { return nil }
func (e *errRefreshRepo) GetByID(_ context.Context, _ uuid.UUID) (*domain.RefreshToken, error) {
	return nil, e.getErr
}
func (e *errRefreshRepo) MarkRevoked(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}
func (e *errRefreshRepo) MarkRotated(_ context.Context, _, _ uuid.UUID, _ time.Time) error {
	return nil
}
func (e *errRefreshRepo) SetAccessJTI(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
	return nil
}
func (e *errRefreshRepo) RevokeAllBySubject(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (e *errRefreshRepo) RevokeByFamily(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (e *errRefreshRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func postRevokeR8(t *testing.T, r *gin.Engine, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// (d) Genuine store I/O error from RevokeJTI → 500.
func TestRevocationR8_RevokeJTIStoreErrorReturns500(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uuid.New().String(), ClientID: "cli-1", Jti: "jti-r8", Exp: exp,
	}}
	ioErr := errors.New("postgres: connection reset")
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	tokenRevSvc := service.NewTokenRevocationService(nil, &errRevocationRepo{insertErr: ioErr})
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService:   service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:         &service.RecorderSessionRevoker{},
		TokenRevocationService: tokenRevSvc,
		ClientAuth:             stubClientAuth{},
		Audit:                  &audit.Recorder{},
	})
	w := postRevokeR8(t, r, "token=valid-access&client_id=cli-1&client_secret=S")
	t.Logf("EVIDENCE (d) RevokeJTI I/O error: status=%d (want 500)", w.Code)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 on genuine JTI store I/O error", w.Code)
	}
	// Response must NOT contain the raw token.
	if strings.Contains(w.Body.String(), "valid-access") {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
}

// (d2) Genuine store I/O error from RevokeByRawToken → 500.
//
// To hit the refresh-token path, we send a selector.validator-shaped token so
// the handler tries the refresh-token branch first (hint=refresh_token).
// The errRefreshRepo.GetByID error causes RevokeByRawToken to return (nil,err).
func TestRevocationR8_RevokeByRawTokenStoreErrorReturns500(t *testing.T) {
	ioErr := errors.New("postgres: deadlock detected")
	refreshSvc := service.NewRefreshTokenService(
		nil,
		&errRefreshRepo{getErr: ioErr},
		service.RefreshTokenServiceOptions{TTL: time.Hour},
	)
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Issue a legitimate token first so we have a valid selector.validator
	// shape (the parse path runs before GetByID).
	validSvc := service.NewRefreshTokenService(
		nil,
		newInMemoryRefreshRepoHandlers(),
		service.RefreshTokenServiceOptions{TTL: time.Hour},
	)
	issued, err := validSvc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-r8", Subject: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{}, nil),
		SessionRevoker:       &service.RecorderSessionRevoker{},
		RefreshTokenService:  refreshSvc, // the erroring service
		ClientAuth:           stubClientAuth{},
		Audit:                &audit.Recorder{},
	})
	// Send with hint=refresh_token so the handler takes the refresh branch.
	form := "token=" + issued.Token + "&token_type_hint=refresh_token&client_id=cli-r8&client_secret=S"
	w := postRevokeR8(t, r, form)
	t.Logf("EVIDENCE (d2) RevokeByRawToken I/O error: status=%d (want 500)", w.Code)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 on genuine refresh-token store I/O error", w.Code)
	}
}

// (e) Invalid / not-found / already-expired token → 200 (RFC 7009 §2.2 preserved).
func TestRevocationR8_InvalidTokenStillReturns200(t *testing.T) {
	// Access token branch: verifier says token is inactive.
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{
			err: errors.New("signature invalid"),
		}, nil),
		SessionRevoker: &service.RecorderSessionRevoker{},
		ClientAuth:     stubClientAuth{},
		Audit:          &audit.Recorder{},
	})
	w := postRevokeR8(t, r, "token=BAD-TOKEN&client_id=cli-1&client_secret=S")
	t.Logf("EVIDENCE (e) invalid token: status=%d (want 200)", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 for invalid token (RFC 7009 §2.2)", w.Code)
	}
}

// (e2) Already-revoked access token (active:false from introspection) → 200.
func TestRevocationR8_AlreadyRevokedTokenReturns200(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Verifier returns claims with Active:false (already revoked / expired).
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil,
			&revFakeVerifier{claims: nil}, // nil claims → inactive
			nil),
		SessionRevoker: &service.RecorderSessionRevoker{},
		ClientAuth:     stubClientAuth{},
		Audit:          &audit.Recorder{},
	})
	w := postRevokeR8(t, r, "token=ALREADY-REVOKED&client_id=cli-1&client_secret=S")
	t.Logf("EVIDENCE (e2) already-revoked token: status=%d (want 200)", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 for already-revoked token", w.Code)
	}
}

// (e3) Not-found refresh token → 200 (falls through to inactive access path).
func TestRevocationR8_NotFoundRefreshTokenReturns200(t *testing.T) {
	emptyRepo := newInMemoryRefreshRepoHandlers() // empty — GetByID returns nil
	refreshSvc := service.NewRefreshTokenService(
		nil, emptyRepo, service.RefreshTokenServiceOptions{TTL: time.Hour},
	)
	// We need a valid selector.validator shape to parse; issue via a temp service.
	tempSvc := service.NewRefreshTokenService(nil, newInMemoryRefreshRepoHandlers(),
		service.RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := tempSvc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-missing", Subject: uuid.New().String(),
	})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{}, nil),
		SessionRevoker:       &service.RecorderSessionRevoker{},
		RefreshTokenService:  refreshSvc, // selector not in this repo → not found
		ClientAuth:           stubClientAuth{},
		Audit:                &audit.Recorder{},
	})
	form := "token=" + issued.Token + "&token_type_hint=refresh_token&client_id=cli-missing&client_secret=S"
	w := postRevokeR8(t, r, form)
	t.Logf("EVIDENCE (e3) not-found refresh token: status=%d (want 200)", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 for not-found refresh token", w.Code)
	}
}

// (f) R4 client-binding: cross-client refresh revoke still returns silent 200.
// The token belongs to cli-A; the revoke request comes from cli-B. The
// handler must return 200 (indistinguishable from real revoke) and must NOT
// actually revoke the row — proving R4 is intact after the R8 refactor.
func TestRevocationR8_R4ClientBindingCrossClientRefreshStillSilent200(t *testing.T) {
	repo := newInMemoryRefreshRepoHandlers()
	refreshSvc := service.NewRefreshTokenService(
		nil, repo, service.RefreshTokenServiceOptions{TTL: time.Hour},
	)
	issued, err := refreshSvc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-A", Subject: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{}, nil),
		SessionRevoker:       &service.RecorderSessionRevoker{},
		RefreshTokenService:  refreshSvc,
		ClientAuth:           stubClientAuth{},
		Audit:                &audit.Recorder{},
	})
	// cli-B presents cli-A's token.
	form := "token=" + issued.Token + "&token_type_hint=refresh_token&client_id=cli-B&client_secret=S"
	w := postRevokeR8(t, r, form)
	t.Logf("EVIDENCE (f) R4 cross-client refresh: status=%d (want 200)", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("R4 cross-client: status=%d, want 200", w.Code)
	}
	// The row must NOT be revoked.
	row := repo.byID[issued.ID]
	if row == nil {
		t.Fatal("refresh row missing")
	}
	t.Logf("EVIDENCE (f) R4 cross-client refresh: revokedAt=%v (want nil)", row.RevokedAt)
	if row.RevokedAt != nil {
		t.Errorf("R4 regression: cross-client revoke actually revoked the row")
	}
}
