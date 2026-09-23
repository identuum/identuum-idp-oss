package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type browserRefreshAudit struct {
	events []audit.Event
}

func (a *browserRefreshAudit) Record(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func TestBrowserRefresh_AuditPreservesSuccessAndReuseWithoutCredentialMetadata(t *testing.T) {
	for _, scenario := range []string{"success", "reuse", "signer_unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			_, repo, minter, issued := browserRefreshFixture(t)
			sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
			user := &domain.User{ID: issued.Session.UserID, Role: domain.RoleOrgUser, Email: "fixture@example.test"}
			tokens := service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{
				Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute, Minter: minter,
			})
			a := &browserRefreshAudit{}
			e := gin.New()
			e.POST("/refresh", HandleBrowserSessionRefresh(AuthSessionsHandlerDeps{
				UserSession: sessions, UserToken: tokens,
				UserLookup: &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{user.ID: user}}, Audit: a,
			}))
			wantStatus, wantAction, wantOutcome := 204, "user_session.refresh.success", "success"
			switch scenario {
			case "reuse":
				if _, err := sessions.RotateRefreshToken(context.Background(), issued.RefreshToken); err != nil {
					t.Fatal("fixture rotation failed")
				}
				past := time.Now().Add(-time.Hour)
				repo.byID[issued.Session.ID].PrevRotatedAt = &past
				wantStatus, wantAction, wantOutcome = 401, "user_session.refresh.reuse_detected", "denied"
			case "signer_unavailable":
				minter.err = errors.New("fixture signer unavailable")
				wantStatus, wantAction = 503, ""
			}
			response := browserRefreshRequest(e, issued.RefreshToken)
			if response.Code != wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, wantStatus)
			}
			if wantAction == "" {
				if len(a.events) != 0 {
					t.Fatal("failed access-token issuance emitted a refresh success")
				}
				return
			}
			if len(a.events) != 1 {
				t.Fatal("browser refresh must emit exactly one audit event for success or detected reuse")
			}
			event := a.events[0]
			if event.Action != wantAction || event.Outcome != wantOutcome {
				t.Error("browser refresh did not preserve the established audit action and outcome")
			}
			if len(event.Metadata) != 0 || event.SubjectID != uuid.Nil {
				t.Error("browser refresh audit must not include credential or session identity metadata")
			}
		})
	}
}

func TestSessionRefresh_AuditDoesNotCarrySessionIdentity(t *testing.T) {
	_, repo, _, issued := browserRefreshFixture(t)
	a := &browserRefreshAudit{}
	e := gin.New()
	e.POST("/refresh", HandleSessionRefresh(AuthSessionsHandlerDeps{
		UserSession: service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{}), Audit: a,
	}))
	body, err := json.Marshal(map[string]string{"refresh_token": issued.RefreshToken})
	if err != nil {
		t.Fatal("fixture request encoding failed")
	}
	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("refresh status = %d, want 200", rec.Code)
	}
	if len(a.events) != 1 || a.events[0].Action != "user_session.refresh.success" || a.events[0].Outcome != "success" {
		t.Fatal("direct refresh must preserve its success audit event")
	}
	if len(a.events[0].Metadata) != 0 {
		t.Error("direct refresh audit contains session identity metadata")
	}
}
