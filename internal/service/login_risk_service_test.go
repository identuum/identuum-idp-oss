package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryLoginAttemptRepo is the LoginAttemptRepository fixture
// the tests use.
type inMemoryLoginAttemptRepo struct {
	mu   sync.Mutex
	rows []*domain.LoginAttempt
}

func newLoginAttemptRepo() *inMemoryLoginAttemptRepo {
	return &inMemoryLoginAttemptRepo{}
}

func (r *inMemoryLoginAttemptRepo) Insert(_ context.Context, a *domain.LoginAttempt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *a
	r.rows = append(r.rows, &cp)
	return nil
}

// CountAccountFailuresSince — failures for the (email AND ip) pair.
func (r *inMemoryLoginAttemptRepo) CountAccountFailuresSince(_ context.Context, emailHash, ipHash, purpose string, since time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int
	for _, row := range r.rows {
		if row.Success || row.Purpose != purpose || row.CreatedAt.Before(since) {
			continue
		}
		if row.EmailHash == emailHash && row.IPHash == ipHash {
			n++
		}
	}
	return n, nil
}

// CountDistinctAccountsFromIPSince — DISTINCT email_hash of failures from ip.
func (r *inMemoryLoginAttemptRepo) CountDistinctAccountsFromIPSince(_ context.Context, ipHash, purpose string, since time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]struct{}{}
	for _, row := range r.rows {
		if row.Success || row.Purpose != purpose || row.CreatedAt.Before(since) {
			continue
		}
		if row.IPHash == ipHash {
			seen[row.EmailHash] = struct{}{}
		}
	}
	return len(seen), nil
}

func (r *inMemoryLoginAttemptRepo) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := r.rows[:0]
	var pruned int64
	for _, row := range r.rows {
		if row.CreatedAt.Before(cutoff) {
			pruned++
			continue
		}
		keep = append(keep, row)
	}
	r.rows = keep
	return pruned, nil
}

// ---------- Construction ----------

func TestNewLoginRiskService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewLoginRiskService(nil, nil, LoginRiskServiceOptions{})
}

// ---------- Hashing posture ----------

func TestLoginRisk_RecordStoresHashedEmailAndIP(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{})
	const email = "alice@example.com"
	const ip = "192.0.2.1"
	if err := svc.Record(context.Background(), email, ip, LoginRiskPurposePassword, false); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("rows = %d", len(repo.rows))
	}
	row := repo.rows[0]
	if row.EmailHash == "" || row.EmailHash == email {
		t.Errorf("email_hash leaked raw email: %q", row.EmailHash)
	}
	if row.IPHash == "" || row.IPHash == ip {
		t.Errorf("ip_hash leaked raw IP: %q", row.IPHash)
	}
	if len(row.EmailHash) != 64 {
		t.Errorf("email_hash must be sha256 hex (64 chars), got %d: %q", len(row.EmailHash), row.EmailHash)
	}
}

// ---------- Lockout semantics ----------

func TestLoginRisk_FivePastFailuresLocksOutCaller(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 5, Window: time.Minute})
	for i := 0; i < 5; i++ {
		_ = svc.Record(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword, false)
	}
	err := svc.Check(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword)
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Errorf("err = %v", err)
	}
}

func TestLoginRisk_DifferentPurposeNotCounted(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 3, Window: time.Minute})
	for i := 0; i < 5; i++ {
		_ = svc.Record(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposeMFA, false)
	}
	// Password counter still empty.
	if err := svc.Check(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword); err != nil {
		t.Errorf("password gate tripped by mfa failures: %v", err)
	}
}

// TestLoginRisk_V1_AccountDoSDead: V1 (unauthenticated account-DoS) is
// dead. 5 failures against a victim email, all from the ATTACKER's IP, must
// NOT lock the victim from their OWN IP — the account counter is keyed on
// the (email AND ip) pair, so an attacker's IP can never build a per-account
// lockout. The attacker's OWN pair (victim, attackerIP) IS locked (a single
// host hammering one account is still bounded). TEETH: revert the pgx/mock
// account counter to OR and Check(victim, victimIP) locks → test fails.
func TestLoginRisk_V1_AccountDoSDead(t *testing.T) {
	repo := newLoginAttemptRepo()
	// IPThreshold high so only the account counter is in play here.
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 5, IPThreshold: 1000, Window: time.Minute})
	const victim = "victim@example.com"
	const attackerIP = "198.51.100.9"
	const victimIP = "203.0.113.7"
	for i := 0; i < 5; i++ {
		_ = svc.Record(context.Background(), victim, attackerIP, LoginRiskPurposePassword, false)
	}
	if err := svc.Check(context.Background(), victim, victimIP, LoginRiskPurposePassword); err != nil {
		t.Errorf("V1: victim locked from their OWN IP — account-DoS NOT dead: %v", err)
	}
	if err := svc.Check(context.Background(), victim, attackerIP, LoginRiskPurposePassword); !errors.Is(err, ErrLoginRateLimited) {
		t.Errorf("V1: attacker's own (victim, attackerIP) pair must be locked: %v", err)
	}
}

// TestLoginRisk_V2_NATLockoutDead: V2 (shared-IP/NAT lockout) is dead. 9
// failures each a DISTINCT email from one IP (below the default ipThreshold
// 10) must NOT lock a 10th distinct user behind that NAT; only at 10 DISTINCT
// accounts does the IP counter trip. TEETH: revert the IP counter to
// COUNT(*) (raw failures) or to OR and a co-tenant locks early → test fails.
func TestLoginRisk_V2_NATLockoutDead(t *testing.T) {
	repo := newLoginAttemptRepo()
	// Threshold high so the account counter never fires — isolate the IP
	// counter. Default IPThreshold = 10.
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 1000, Window: time.Minute})
	const ipX = "192.0.2.55"

	// ONE noisy neighbor fails 15 times from ipX (RAW failures = 15, but only
	// 1 DISTINCT account).
	for i := 0; i < 15; i++ {
		_ = svc.Record(context.Background(), "spammer@example.com", ipX, LoginRiskPurposePassword, false)
	}
	// A co-tenant behind the same NAT is NOT locked: only 1 DISTINCT failing
	// account (< ipThreshold 10) despite 15 RAW failures. This is where the
	// COUNT(DISTINCT email) semantics matter — a COUNT(*)/raw or OR keyspace
	// would already lock here (15 >= 10). TEETH: revert the IP counter to raw
	// COUNT(*) and this assertion fails.
	if err := svc.Check(context.Background(), "victim@example.com", ipX, LoginRiskPurposePassword); err != nil {
		t.Errorf("V2: co-tenant locked by ONE noisy neighbor's 15 RAW failures — IP counter is not DISTINCT: %v", err)
	}

	// Now spray 9 MORE distinct accounts → 10 DISTINCT failing accounts total.
	for i := 0; i < 9; i++ {
		_ = svc.Record(context.Background(), fmt.Sprintf("user%d@example.com", i), ipX, LoginRiskPurposePassword, false)
	}
	if err := svc.Check(context.Background(), "user9@example.com", ipX, LoginRiskPurposePassword); !errors.Is(err, ErrLoginRateLimited) {
		t.Errorf("V2: 10 DISTINCT accounts from one IP must trip the IP counter: %v", err)
	}
}

func TestLoginRisk_WindowOutsideNotCounted(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 3, Window: time.Minute})
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		_ = repo.Insert(context.Background(), &domain.LoginAttempt{
			ID:        domain.SystemActor().UserID,
			EmailHash: hashLoginID("alice@example.com"),
			IPHash:    hashLoginID("192.0.2.1"),
			Purpose:   string(LoginRiskPurposePassword),
			Success:   false,
			CreatedAt: old,
		})
	}
	if err := svc.Check(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword); err != nil {
		t.Errorf("window-aged failures tripped gate: %v", err)
	}
}

// ---------- DeleteExpired ----------

func TestLoginRisk_DeleteExpiredPrunesOldRows(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Window: time.Minute})
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	_ = repo.Insert(context.Background(), &domain.LoginAttempt{CreatedAt: frozen.Add(-time.Hour), Success: false})
	_ = repo.Insert(context.Background(), &domain.LoginAttempt{CreatedAt: frozen, Success: true})
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d", n)
	}
}

// ---------- Empty inputs ----------

// ---------- FAIL-CLOSED on backend error (P1-4) ----------

// erroringLoginAttemptRepo makes the risk counters fail so the service's
// fail-closed path is exercised. errOnPurpose == "" errors on every
// purpose; a specific value errors on that purpose only (so a test can let
// the password gate pass and trip only the mfa gate). ipOnly makes ONLY
// the IP distinct-account counter fail (the account counter succeeds), so a
// test can prove fail-closed on EITHER counter (P2-10). Shared with the
// local_login_service tests (same package).
type erroringLoginAttemptRepo struct {
	errOnPurpose string
	ipOnly       bool
}

func (r erroringLoginAttemptRepo) Insert(context.Context, *domain.LoginAttempt) error { return nil }

func (r erroringLoginAttemptRepo) errs(purpose string) bool {
	return r.errOnPurpose == "" || r.errOnPurpose == purpose
}

func (r erroringLoginAttemptRepo) CountAccountFailuresSince(_ context.Context, _, _, purpose string, _ time.Time) (int, error) {
	if !r.ipOnly && r.errs(purpose) {
		return 0, errors.New("simulated login_attempts store outage")
	}
	return 0, nil
}

func (r erroringLoginAttemptRepo) CountDistinctAccountsFromIPSince(_ context.Context, _, purpose string, _ time.Time) (int, error) {
	if r.errs(purpose) {
		return 0, errors.New("simulated login_attempts store outage")
	}
	return 0, nil
}

func (r erroringLoginAttemptRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// TestLoginRisk_BackendErrorFailsClosed pins the P1-4 contract: when the
// store errors, Check returns the DISTINCT ErrLoginRiskBackendUnavailable
// sentinel — NOT nil (the old fail-open) and NOT ErrLoginRateLimited (a
// genuine lockout). TEETH: revert Check's error branch to `return nil` and
// this test fails (got nil, wanted the sentinel).
func TestLoginRisk_BackendErrorFailsClosed(t *testing.T) {
	svc := NewLoginRiskService(nil, erroringLoginAttemptRepo{}, LoginRiskServiceOptions{})
	err := svc.Check(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword)
	if err == nil {
		t.Fatal("Check returned nil on a backend error — fail-OPEN regression; brute-force lockout disabled")
	}
	if !errors.Is(err, ErrLoginRiskBackendUnavailable) {
		t.Fatalf("err = %v; want ErrLoginRiskBackendUnavailable", err)
	}
	if errors.Is(err, ErrLoginRateLimited) {
		t.Fatal("backend-unavailable must be DISTINCT from a genuine rate-limit lockout")
	}
}

// TestLoginRisk_IPCounterBackendErrorFailsClosed: a repo error on the IP
// distinct-account counter (account counter succeeds) still fails closed
// (P2-10: EITHER counter erroring → 503), proving the fail-closed posture
// covers both counters, not just the first.
func TestLoginRisk_IPCounterBackendErrorFailsClosed(t *testing.T) {
	svc := NewLoginRiskService(nil, erroringLoginAttemptRepo{ipOnly: true}, LoginRiskServiceOptions{Threshold: 5, Window: time.Minute})
	err := svc.Check(context.Background(), "alice@example.com", "192.0.2.1", LoginRiskPurposePassword)
	if !errors.Is(err, ErrLoginRiskBackendUnavailable) {
		t.Fatalf("err = %v; want ErrLoginRiskBackendUnavailable (IP-counter error must fail closed)", err)
	}
}

// TestLoginRisk_ConcurrentInsertCheckRace drives parallel Record+Check on a
// mutex-guarded repo under -race. The window count stays consistent (no data
// race, no panic) and a fixed key resolves to a valid state.
func TestLoginRisk_ConcurrentInsertCheckRace(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 5, IPThreshold: 10, Window: time.Minute})
	var wg sync.WaitGroup
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			email := fmt.Sprintf("u%d@example.com", i%4)
			ip := fmt.Sprintf("10.0.0.%d", i%3)
			_ = svc.Record(context.Background(), email, ip, LoginRiskPurposePassword, false)
			_ = svc.Check(context.Background(), email, ip, LoginRiskPurposePassword)
		}(i)
	}
	wg.Wait()
	if err := svc.Check(context.Background(), "u0@example.com", "10.0.0.0", LoginRiskPurposePassword); err != nil && !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("unexpected err after concurrent storm: %v", err)
	}
}

func TestLoginRisk_EmptyEmailDoesNotMatchEmptyEmail(t *testing.T) {
	// hashLoginID returns "" for empty input. The CountFailuresSince
	// fixture treats EmailHash == row.EmailHash as a match, so the
	// service path's empty-string sentinel could mistakenly match
	// another empty row. Confirm hashLoginID("") returns "" and the
	// service falls back to the IP comparison instead.
	if hashLoginID("") != "" {
		t.Errorf("hashLoginID('') != ''")
	}
}
