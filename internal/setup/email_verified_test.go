package setup

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-0912-C2: the setup wizard's site_admin is activated, and its address is
// recorded as set at setup, not proven (its login is site_admin@system.local).
func TestComplete_SiteAdminAddressIsSetNotProven(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	if _, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	h.userRepo.mu.Lock()
	defer h.userRepo.mu.Unlock()
	if len(h.userRepo.users) != 1 {
		t.Fatalf("expected one user, got %d", len(h.userRepo.users))
	}
	u := h.userRepo.users[0]
	if !u.EmailVerified || u.EmailVerifiedVia == nil || *u.EmailVerifiedVia != domain.EmailVerifiedViaSetup || u.MailboxProven() {
		t.Errorf("site_admin email_verified %v via %v; want activated, via setup, not proven", u.EmailVerified, u.EmailVerifiedVia)
	}
}
