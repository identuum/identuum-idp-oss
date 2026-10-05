package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// FUNC-M2 (audits/oss-functionality-2026-10-05.md): after five wrong
// passwords from one address the right one was answered invalid_credentials,
// with no wait hint, while the v0.9.5 notes promise that repeated failures
// slow sign-in down (429 login_throttled with Retry-After) and never lock.
// The bounds stay exactly as strong; only the answer changes: a correct
// password is never told it is wrong.

func lockAnswerHarness(t *testing.T) (*LocalLoginService, *LoginRiskService, time.Time) {
	t.Helper()
	svc, users := newLoginHarness(t)
	frozen := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	risk := NewLoginRiskService(nil, newLoginAttemptRepo(), LoginRiskServiceOptions{})
	risk.now = func() time.Time { return frozen }
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	return svc.WithLoginRiskService(risk), risk, frozen
}

func TestLogin_TheRightPasswordAfterFiveFailuresIsToldToWait(t *testing.T) {
	svc, _, _ := lockAnswerHarness(t)
	ip := "192.0.2.10"
	for i := 0; i < 5; i++ {
		_, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "wrong", IPAddress: &ip})
	}
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct", IPAddress: &ip})
	if errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatal("the right password was answered invalid credentials")
	}
	var throttled *LoginThrottledError
	if !errors.As(err, &throttled) || !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("err = %v; want a LoginThrottledError (429 login_throttled)", err)
	}
	// The five failures were recorded at the same instant; the pair counter
	// drops below its threshold when they leave the 15-minute window.
	if throttled.RetryAfter != 15*time.Minute {
		t.Errorf("RetryAfter = %v; want 15m (until the oldest counted failure leaves the window)", throttled.RetryAfter)
	}
}

func TestLoginRisk_TheIPSprayBoundAnswersWithAWait(t *testing.T) {
	_, risk, frozen := lockAnswerHarness(t)
	ip := "192.0.2.11"
	for i := 0; i < 10; i++ {
		email := "victim" + string(rune('a'+i)) + "@example.com"
		if err := risk.Record(context.Background(), email, ip, LoginRiskPurposePassword, false); err != nil {
			t.Fatal(err)
		}
	}
	risk.now = func() time.Time { return frozen.Add(time.Minute) }
	err := risk.Check(context.Background(), "someone@example.com", ip, LoginRiskPurposePassword)
	var throttled *LoginThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("err = %v; want a LoginThrottledError", err)
	}
	if throttled.RetryAfter != 14*time.Minute {
		t.Errorf("RetryAfter = %v; want 14m", throttled.RetryAfter)
	}
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Error("a bound that holds is still ErrLoginRateLimited to its callers")
	}
}
