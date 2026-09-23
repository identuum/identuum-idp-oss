package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type refreshRevocationFailureRepo struct{ *browserRefreshRepo }

func (r *refreshRevocationFailureRepo) RevokeByUserID(context.Context, uuid.UUID, string) error {
	return errors.New("fixture private store diagnostic")
}

func TestRefresh_RevocationFailureRefusesWithoutHidingTheOperationalFailure(t *testing.T) {
	for _, browser := range []bool{false, true} {
		name := "direct"
		if browser {
			name = "browser"
		}
		t.Run(name, func(t *testing.T) {
			_, base, minter, issued := browserRefreshFixture(t)
			sessions := service.NewUserSessionService(nil, &refreshRevocationFailureRepo{base}, service.UserSessionServiceOptions{})
			if _, err := sessions.RotateRefreshToken(context.Background(), issued.RefreshToken); err != nil {
				t.Fatal("fixture rotation failed")
			}
			past := time.Now().Add(-time.Hour)
			base.byID[issued.Session.ID].PrevRotatedAt = &past
			user := &domain.User{ID: issued.Session.UserID, Role: domain.RoleOrgUser, Email: "fixture@example.test"}
			a := &browserRefreshAudit{}
			deps := AuthSessionsHandlerDeps{
				UserSession: sessions, Audit: a,
				UserLookup: &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{user.ID: user}},
				UserToken: service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{
					Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute, Minter: minter,
				}),
			}
			e := gin.New()
			var rec *httptest.ResponseRecorder
			if browser {
				e.POST("/refresh", HandleBrowserSessionRefresh(deps))
				rec = browserRefreshRequest(e, issued.RefreshToken)
			} else {
				e.POST("/refresh", HandleSessionRefresh(deps))
				body, err := json.Marshal(map[string]string{"refresh_token": issued.RefreshToken})
				if err != nil {
					t.Fatal("fixture request encoding failed")
				}
				req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				rec = httptest.NewRecorder()
				e.ServeHTTP(rec, req)
			}
			if rec.Code != 503 {
				t.Errorf("revocation failure status = %d, want 503", rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("refresh response must prohibit storage")
			}
			if len(rec.Result().Cookies()) != 0 || len(minter.claims) != 0 {
				t.Error("unconfirmed revocation must not issue credentials or change cookies")
			}
			var body map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["error"] != "refresh_unavailable" {
				t.Error("response did not report refresh unavailability")
			}
			for _, forbidden := range []string{issued.RefreshToken, issued.Session.ID.String(), "fixture private store diagnostic"} {
				if strings.Contains(rec.Body.String(), forbidden) {
					t.Error("refresh error response exposes private data")
				}
			}
			if len(a.events) != 1 {
				t.Fatal("detected reuse must emit exactly one audit event")
			}
			event := a.events[0]
			if event.Action != "user_session.refresh.reuse_detected" || event.Outcome != "denied" {
				t.Error("revocation failure lost the detected-reuse audit verdict")
			}
			if len(event.Metadata) != 1 || event.Metadata["revocation"] != "unconfirmed" {
				t.Error("reuse audit did not mark revocation unconfirmed with safe metadata")
			}
		})
	}
}
