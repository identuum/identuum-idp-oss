package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRotate_ReuseAlertDoesNotExposeSessionIdentity(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	previous := logger.Error
	logger.Error = logger.NewLogger(zap.New(core), zap.ErrorLevel)
	t.Cleanup(func() { logger.Error = previous })
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	uid := uuid.New()
	first, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatal("fixture session creation failed")
	}
	if _, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken); err != nil {
		t.Fatal("fixture rotation failed")
	}
	if _, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken); !errors.Is(err, ErrUserSessionReuse) {
		t.Fatal("reuse was not refused")
	}
	if active, err := repo.ListActiveByUserID(context.Background(), uid); err != nil || len(active) != 0 {
		t.Fatal("reuse did not revoke the session family")
	}
	events := observed.All()
	if len(events) != 1 || !strings.Contains(events[0].Message, "refresh-token reuse detected") {
		t.Fatal("reuse security alert was not retained")
	}
	fields := events[0].ContextMap()
	if _, exists := fields["session_id"]; exists {
		t.Error("reuse alert includes a forbidden session identity field")
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal("could not inspect captured alert fields")
	}
	for _, forbidden := range []string{first.Session.ID.String(), first.RefreshToken} {
		if strings.Contains(string(encoded), forbidden) || strings.Contains(events[0].Message, forbidden) {
			t.Error("reuse alert exposes session identity or credentials")
		}
	}
}
