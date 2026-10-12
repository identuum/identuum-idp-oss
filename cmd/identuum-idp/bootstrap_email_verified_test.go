package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-0912-C2: the bootstrapped site_admin is activated, and its address is
// recorded as set at setup, not proven (its login may not be a mailbox).
func TestBootstrapCore_SiteAdminAddressIsSetNotProven(t *testing.T) {
	t.Parallel()
	deps := bootstrapDeps{Keys: &memKeyRepo{}, Users: &memUserRepo{}}
	var stdout, stderr bytes.Buffer
	if rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr); rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}
	users := deps.Users.(*memUserRepo).users
	if len(users) != 1 {
		t.Fatalf("expected one user, got %d", len(users))
	}
	u := users[0]
	if !u.EmailVerified || u.EmailVerifiedVia == nil || *u.EmailVerifiedVia != domain.EmailVerifiedViaSetup || u.MailboxProven() {
		t.Errorf("site_admin email_verified %v via %v; want activated, via setup, not proven", u.EmailVerified, u.EmailVerifiedVia)
	}
}
