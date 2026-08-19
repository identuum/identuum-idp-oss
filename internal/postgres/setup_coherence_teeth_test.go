//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"
)

// SETUP-COHERENCE-1 (WIZARD-SPLIT-BRAIN-1). The DB refuses to mark setup
// 'setup_complete' unless a live site_admin exists — the setup-state row and
// the site_admin's existence may never disagree. Both real completion paths
// (the wizard's Complete, and bootstrap) create the site_admin BEFORE flipping
// the state, so the tooth never blocks them; it blocks the incoherent
// "complete with no admin" state past every service guard.
//
// Everything runs inside ONE transaction that is ROLLED BACK, so the shared
// test database is left byte-untouched. TRUNCATE (not DELETE) clears users
// without firing the sentinel-protection row triggers — the same escape the
// setup-replay suite uses.
// RULE: SETUP-COHERENCE-1
func TestSetupCompleteRequiresSiteAdmin(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Clean slate: no users (hence no site_admin), state back to required.
	if _, err := tx.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate users: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE system_setup_state SET status='setup_required'`); err != nil {
		t.Fatalf("reset setup state: %v", err)
	}

	// REFUSAL: marking complete with no site_admin must RAISE.
	if _, err := tx.Exec(ctx, `UPDATE system_setup_state SET status='setup_complete'`); err == nil {
		t.Fatal("marking setup complete with NO site_admin SUCCEEDED — the coherence tooth is not holding; " +
			"a support script or restore could leave setup_complete with no way to log in")
	} else if !strings.Contains(err.Error(), "without a live site_admin") {
		t.Fatalf("refused, but with the wrong message: %v", err)
	}

	// The failed statement aborts the transaction; restart a clean one for the
	// positive control.
	_ = tx.Rollback(ctx)
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()

	if _, err := tx2.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate users (2): %v", err)
	}
	// A live site_admin in the System organization (seeded by migration 0001).
	if _, err := tx2.Exec(ctx, `
		INSERT INTO users
			(id, email, password_hash, organization_id, role, banned, email_verified,
			 mfa_enabled, auth_source, requires_password_change, oidc_linked, created_at, updated_at)
		VALUES
			('00000000-0000-7000-0000-000000000001', 'site_admin@system.local', 'x',
			 '00000000-0000-7000-0000-000000000000', 'site_admin', false, true,
			 false, 'local', false, false, now(), now())`); err != nil {
		t.Fatalf("insert site_admin: %v", err)
	}
	if _, err := tx2.Exec(ctx, `UPDATE system_setup_state SET status='setup_required'`); err != nil {
		t.Fatalf("reset setup state (2): %v", err)
	}
	// POSITIVE CONTROL: with a live site_admin, the same update must SUCCEED.
	if _, err := tx2.Exec(ctx, `UPDATE system_setup_state SET status='setup_complete'`); err != nil {
		t.Fatalf("with a live site_admin present, marking setup complete must succeed; got: %v", err)
	}
}
