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

type reuseRevocationFailureRepo struct {
	*inMemoryUserSessionRepo
	revokeErr error
	attempts  int
}

func (r *reuseRevocationFailureRepo) RevokeByUserID(ctx context.Context, id uuid.UUID, reason string) error {
	r.attempts++
	if r.revokeErr != nil {
		return r.revokeErr
	}
	return r.inMemoryUserSessionRepo.RevokeByUserID(ctx, id, reason)
}

func TestRotate_ReuseRevocationFailureIsUnavailableAndRemainsRefused(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	previous := logger.Error
	logger.Error = logger.NewLogger(zap.New(core), zap.ErrorLevel)
	t.Cleanup(func() { logger.Error = previous })
	storeErr := errors.New("fixture private store diagnostic")
	repo := &reuseRevocationFailureRepo{inMemoryUserSessionRepo: newSessionRepo(), revokeErr: storeErr}
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	uid := uuid.New()
	first, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatal("fixture session creation failed")
	}
	if _, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken); err != nil {
		t.Fatal("fixture rotation failed")
	}
	issued, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if issued != nil || !errors.Is(err, ErrUserSessionReuse) {
		t.Fatal("failed family revocation must still refuse the replay")
	}
	if !errors.Is(err, ErrUserSessionUnavailable) {
		t.Error("failed family revocation was not reported as unavailable")
	}
	if repo.attempts != 1 {
		t.Error("one request must make one family-revocation attempt")
	}
	if strings.Contains(err.Error(), storeErr.Error()) {
		t.Error("public service error exposes raw store diagnostics")
	}
	events := observed.All()
	if len(events) != 1 || !strings.Contains(events[0].Message, "revocation unconfirmed") {
		t.Error("security alert does not name the unconfirmed revocation")
	}
	for _, event := range events {
		fields, marshalErr := json.Marshal(event.ContextMap())
		if marshalErr != nil {
			t.Fatal("could not inspect captured alert")
		}
		for _, forbidden := range []string{first.Session.ID.String(), first.RefreshToken, storeErr.Error()} {
			if strings.Contains(event.Message+string(fields), forbidden) {
				t.Error("unconfirmed-revocation alert exposes private data")
			}
		}
	}
	// Recovery is a new observation of a working store, not a silent retry
	// inside the failed request. Reuse remains refused after the write succeeds.
	repo.revokeErr = nil
	issued, err = svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if issued != nil || !errors.Is(err, ErrUserSessionReuse) || errors.Is(err, ErrUserSessionUnavailable) {
		t.Error("confirmed revocation did not retain the ordinary reuse refusal")
	}
	if active, err := repo.ListActiveByUserID(context.Background(), uid); err != nil || len(active) != 0 {
		t.Error("recovered store did not revoke the family")
	}
}
