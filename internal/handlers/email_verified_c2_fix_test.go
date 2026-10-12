package handlers

// OSS-0912-C2-FIX (review OSS-0912-C2-REVIEW R1, R4): the wire answers for a
// link mailed to an earlier address and for the site_admin's own send.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// c2FixVerifs holds one live row.
type c2FixVerifs struct {
	c2Verifs
	row *domain.EmailVerification
}

func (v *c2FixVerifs) GetByTokenHash(_ context.Context, hash string) (*domain.EmailVerification, error) {
	if v.row != nil && v.row.TokenHash == hash {
		return v.row, nil
	}
	return nil, nil
}

func TestVerifyEmailRoute_LinkForAnEarlierAddress(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	user := &domain.User{ID: uuid.New(), Email: "new@example.com", EmailVerified: true}
	users := &c2Users{byID: map[uuid.UUID]*domain.User{user.ID: user}}
	const raw = "c2-fix-raw-token"
	verifs := &c2FixVerifs{row: &domain.EmailVerification{
		UserID: user.ID, TokenHash: crypto.HashToken(raw), AddressHash: domain.EmailAddressHash("old@example.com"),
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	svc := service.NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, service.EmailVerificationServiceOptions{})
	r := gin.New()
	RegisterAccountLifecycleRoutes(r, AccountLifecycleHandlerDeps{EmailVerify: svc})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token="+raw, nil))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if w.Code != http.StatusBadRequest || m["error"] != "email_changed" || m["message"] == nil {
		t.Errorf("verify-email with a link for an earlier address = %d %v; want 400 email_changed with a message", w.Code, m)
	}
}

func TestSendOwnVerificationRoute_SiteAdminIsRefused(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	site := &domain.User{ID: uuid.New(), Email: domain.SiteAdminEmail, Role: domain.RoleSiteAdmin, EmailVerified: true,
		EmailVerifiedVia: userinfoStrPtr(domain.EmailVerifiedViaSetup)}
	users := &c2Users{byID: map[uuid.UUID]*domain.User{site.ID: site}}
	n := &c2Notifier{}
	svc := service.NewEmailVerificationService(users, &c2Verifs{}, n, audit.NoopService{}, service.EmailVerificationServiceOptions{})
	r := gin.New()
	r.Use(func(c *gin.Context) {
		mw.SetPrincipal(c, &domain.Principal{UserID: site.ID, Role: domain.RoleSiteAdmin})
		c.Next()
	})
	RegisterAccountLifecycleRoutes(r, AccountLifecycleHandlerDeps{EmailVerify: svc})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verification", nil))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if w.Code != http.StatusConflict || m["error"] != "not_available_for_this_account" || n.sends != 0 {
		t.Errorf("site_admin send = %d %v (sends %d); want 409 not_available_for_this_account and no mail", w.Code, m, n.sends)
	}
}
