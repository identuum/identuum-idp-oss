package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Owner ruling (v0.9.5): after 5 failed password sign-ins for one account
// within the window, from any address, each further attempt must wait
// 1, 2, 4 … seconds after the last failure, never more than 60 — a slow-down,
// never a lockout. Inside the wait the password is not looked at. A
// successful sign-in starts the count again.

func slowDownRisk(t *testing.T) (*LoginRiskService, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	svc := NewLoginRiskService(nil, newLoginAttemptRepo(), LoginRiskServiceOptions{})
	svc.now = func() time.Time { return now }
	return svc, &now
}

func failFrom(t *testing.T, svc *LoginRiskService, email string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := svc.Record(context.Background(), email, fmt.Sprintf("203.0.113.%d", i+1), LoginRiskPurposePassword, false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginRisk_AccountWideSlowDownDoublesUpToAMinute(t *testing.T) {
	const email = "victim@acme.test"
	fresh := "198.51.100.1" // never failed: only the account-wide rule can apply
	for n, want := range map[int]time.Duration{
		5: time.Second, 6: 2 * time.Second, 7: 4 * time.Second, 8: 8 * time.Second,
		9: 16 * time.Second, 10: 32 * time.Second, 11: time.Minute, 30: time.Minute,
	} {
		svc, now := slowDownRisk(t)
		failFrom(t, svc, email, n)
		err := svc.Check(context.Background(), email, fresh, LoginRiskPurposePassword)
		var th *LoginThrottledError
		if !errors.Is(err, ErrLoginThrottled) || !errors.As(err, &th) || th.RetryAfter != want {
			t.Errorf("after %d failures: err = %v, want a %s slow-down", n, err, want)
			continue
		}
		*now = now.Add(want)
		if err := svc.Check(context.Background(), email, fresh, LoginRiskPurposePassword); err != nil {
			t.Errorf("after %d failures and the %s wait: err = %v, want allowed", n, want, err)
		}
	}
}

func TestLoginRisk_FourFailuresDoNotSlowDownAndASuccessStartsAgain(t *testing.T) {
	const email = "victim@acme.test"
	svc, _ := slowDownRisk(t)
	failFrom(t, svc, email, 4)
	if err := svc.Check(context.Background(), email, "198.51.100.1", LoginRiskPurposePassword); err != nil {
		t.Fatalf("after 4 failures: err = %v, want allowed", err)
	}
	failFrom(t, svc, email, 1)
	if err := svc.Check(context.Background(), email, "198.51.100.1", LoginRiskPurposePassword); !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("after 5 failures: err = %v, want a slow-down", err)
	}
	if err := svc.Record(context.Background(), email, "198.51.100.2", LoginRiskPurposePassword, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.Check(context.Background(), email, "198.51.100.1", LoginRiskPurposePassword); err != nil {
		t.Errorf("after a successful sign-in: err = %v, want the count started again", err)
	}
}

func TestLoginRisk_SlowDownIsPerAccountAndPasswordOnly(t *testing.T) {
	svc, _ := slowDownRisk(t)
	failFrom(t, svc, "victim@acme.test", 8)
	if err := svc.Check(context.Background(), "other@acme.test", "198.51.100.1", LoginRiskPurposePassword); err != nil {
		t.Errorf("another account: err = %v, want allowed", err)
	}
	if err := svc.Check(context.Background(), "victim@acme.test", "198.51.100.1", LoginRiskPurposeMFA); err != nil {
		t.Errorf("the mfa purpose: err = %v, want allowed (its own bounds apply)", err)
	}
}

// A parallel burst against one account from many addresses reaches the
// password check only up to the slow-down's threshold: the attempts for one
// account are serialized, so each sees the failures recorded before it.
func TestLogin_AParallelBurstFromManyAddressesSlowsDown(t *testing.T) {
	const burst = 40
	svc, users := newLoginHarness(t)
	repo := newLoginAttemptRepo()
	svc = svc.WithLoginRiskService(NewLoginRiskService(nil, repo, LoginRiskServiceOptions{}))
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	throttled := 0
	for i := 0; i < burst; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "wrong", IPAddress: &ip})
			if errors.Is(err, ErrLoginThrottled) {
				mu.Lock()
				throttled++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	repo.mu.Lock()
	checked := len(repo.rows)
	repo.mu.Unlock()
	if checked > 5 || throttled != burst-checked {
		t.Errorf("%d of %d wrong passwords from %d addresses reached the password check (%d slowed down); want at most 5, the rest slowed down", checked, burst, burst, throttled)
	}
}
