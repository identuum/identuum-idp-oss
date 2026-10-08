package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// F7 (SEC-MFA-REVIEW-2026-10-08, owner ruling bb): when an organization
// makes MFA required, a session without MFA keeps working until its next
// refresh; then the refresh is refused and the user must complete MFA. A
// session that did MFA (or was lifted to it) still refreshes; nothing is
// signed out.
func TestRotate_RequiredMFAPolicyNeedsAnMFASession(t *testing.T) {
	cases := []struct {
		name, policy, acr string
		ok                bool
	}{
		{"required, password session", "required", auth.ACRPassword, false},
		{"required, session without acr", "required", "", false},
		{"required, MFA session", "required", auth.ACRMFA, true},
		{"required, phishing-resistant session", "required", auth.ACRPhishingResistant, true},
		{"optional, password session", "optional", auth.ACRPassword, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newSessionRepo()
			svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
			uid := uuid.New()
			issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid, Acr: tc.acr})
			if err != nil {
				t.Fatal(err)
			}
			repo.statusInfo = &domain.SessionValidationInfo{UserActive: true, OrgActive: true, OrgMFAPolicy: tc.policy}
			_, err = svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
			if tc.ok != (err == nil) {
				t.Fatalf("rotate: %v; want success %v", err, tc.ok)
			}
			if !tc.ok && !errors.Is(err, ErrUserSessionMFARequired) {
				t.Fatalf("rotate: %v; want ErrUserSessionMFARequired", err)
			}
			if active, _ := repo.ListActiveByUserID(context.Background(), uid); len(active) != 1 {
				t.Fatalf("%d active session(s) after the refresh; ruling bb signs nobody out", len(active))
			}
		})
	}
	t.Run("a session lifted to MFA by step-up refreshes", func(t *testing.T) {
		repo := newSessionRepo()
		svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
		issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New(), Acr: auth.ACRPassword})
		if err != nil {
			t.Fatal(err)
		}
		lifted := auth.ACRMFA
		repo.byID[issued.Session.ID].LastACRUpliftValue = &lifted
		repo.statusInfo = &domain.SessionValidationInfo{UserActive: true, OrgActive: true, OrgMFAPolicy: "required"}
		if _, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken); err != nil {
			t.Fatalf("a step-up-lifted session was refused: %v", err)
		}
	})
}
