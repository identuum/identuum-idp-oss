package service

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// The lockout counts failures that are already recorded, so a burst of requests
// that all start before the first failure is recorded would all be checked. The
// attempts for one account from one address are serialized: only the threshold's
// worth reach the password check, however many arrive at once.
func TestLogin_AParallelBurstIsCheckedOnlyUpToTheThreshold(t *testing.T) {
	const threshold = 5
	const burst = 40
	svc, users := newLoginHarness(t)
	repo := newLoginAttemptRepo()
	svc = svc.WithLoginRiskService(NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: threshold}))
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	ip := "192.0.2.7"

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "wrong", IPAddress: &ip})
		}()
	}
	close(start)
	wg.Wait()

	repo.mu.Lock()
	checked := len(repo.rows)
	repo.mu.Unlock()
	if checked > threshold {
		t.Errorf("%d of %d parallel wrong passwords reached the password check; want at most %d", checked, burst, threshold)
	}
}

// The serialization is per account and address: a burst from one address does not
// make another address, or another account, wait or lock.
func TestLogin_ABurstDoesNotLockOtherCallers(t *testing.T) {
	svc, users := newLoginHarness(t)
	repo := newLoginAttemptRepo()
	svc = svc.WithLoginRiskService(NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 3}))
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	attacker, owner := "192.0.2.7", "198.51.100.9"

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "wrong", IPAddress: &attacker})
		}()
	}
	wg.Wait()

	if _, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct", IPAddress: &owner}); err != nil {
		t.Errorf("the account's owner from another address = %v; want a successful sign-in", err)
	}
}
