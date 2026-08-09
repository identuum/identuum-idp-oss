//go:build integration

// Package e2e — P0-3b regression: soft-deleting an organization must
// PROACTIVELY revoke its live long-lived credentials, ATOMICALLY with the
// existing soft-delete cascade. Before P0-3b the cascade set deleted_at on
// users / service_accounts / identity_providers / oauth_clients / the org
// row, but left the org's LIVE sessions (days) and refresh tokens (30d) valid
// to their own expiry — leaving use-time org-liveness (P0-3/4/5) as the only
// layer. PgxOrganizationRepository.Delete now also, in the SAME tx:
//   - revokes sessions      (is_valid=false, revoked_at, revoked_reason)
//   - revokes refresh tokens (revoked_at)
//   - deletes oidc_states    (the soft delete never fires the FK CASCADE)
//   - burns live auth codes  (consumed_at)
//
// These pins run against real Postgres so the org-scoping predicates (which
// live in SQL) and the all-or-nothing transaction are exercised end to end.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/... -run OrgDeleteCredentialRevoke
//
// Safety: no secret / hash / DB URL is echoed. Each seed org is hard-deleted
// on cleanup; refresh tokens + auth codes (no org FK) are reaped explicitly.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// seededCreds is the handle to one org's seeded credential set.
type seededCreds struct {
	orgID     uuid.UUID
	userID    uuid.UUID
	sessionID uuid.UUID
	refreshID uuid.UUID
	state     string
	codeID    uuid.UUID
}

func TestE2E_OSS_OrgDeleteCredentialRevoke(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	// seedOrgWithCreds seeds an active org plus a user and one LIVE row in
	// each long-lived-credential table (session, refresh token, oidc_state,
	// auth code), and schedules cleanup. Cleanup hard-deletes the org (FK
	// CASCADE reaps users → sessions and oidc_states); refresh tokens and
	// auth codes have no org FK, so they are removed explicitly.
	seedOrgWithCreds := func(t *testing.T) seededCreds {
		t.Helper()
		suffix := uuid.NewString()
		org, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:      "e2e-delorg-" + suffix,
			Domain:    "e2e-delorg-" + suffix + ".example.invalid",
			OrgSlug:   "e2e-delorg-" + suffix[:8],
			Active:    true,
			MFAPolicy: "optional",
		})
		if err != nil {
			t.Fatalf("seed org: %v", err)
		}

		userID := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, email, password_hash, organization_id, role)
			 VALUES ($1, $2, 'placeholder-not-a-real-hash', $3, 'org_user')`,
			userID, "e2e-user-"+suffix+"@example.invalid", org.ID); err != nil {
			t.Fatalf("seed user: %v", err)
		}

		exp := time.Now().Add(24 * time.Hour)

		sessionID := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO sessions (id, user_id, token_selector, token_validator_hash, expires_at)
			 VALUES ($1, $2, $3, 'placeholder-validator-hash', $4)`,
			sessionID, userID, uuid.New(), exp); err != nil {
			t.Fatalf("seed session: %v", err)
		}

		refreshID := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO oauth_refresh_tokens (id, validator_hash, client_id, client_kind, subject, expires_at)
			 VALUES ($1, 'placeholder-validator-hash', 'e2e-client', 'confidential', $2, $3)`,
			refreshID, userID.String(), time.Now().Add(30*24*time.Hour)); err != nil {
			t.Fatalf("seed refresh token: %v", err)
		}

		// oidc_states.provider_id has an FK to identity_providers, so seed a
		// provider under this org first.
		providerID := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_providers (id, organization_id, type, name, slug)
			 VALUES ($1, $2, 'oidc', 'e2e-provider', $3)`,
			providerID, org.ID, "e2e-idp-"+suffix[:8]); err != nil {
			t.Fatalf("seed provider: %v", err)
		}

		state := "e2e-state-" + suffix
		if _, err := pool.Exec(ctx,
			`INSERT INTO oidc_states (state, organization_id, provider_id, nonce, pkce_verifier_encrypted, redirect_uri, expires_at)
			 VALUES ($1, $2, $3, 'e2e-nonce', 'e2e-enc', 'https://app.example.com/cb', $4)`,
			state, org.ID, providerID, time.Now().Add(10*time.Minute)); err != nil {
			t.Fatalf("seed oidc_state: %v", err)
		}

		codeID := uuid.New()
		if _, err := pool.Exec(ctx,
			`INSERT INTO oauth_authorization_codes
			   (id, code_hash, client_id, user_id, organization_id, session_id, redirect_uri, code_challenge, code_challenge_method, expires_at)
			 VALUES ($1, $2, 'e2e-client', $3, $4, $5, 'https://app.example.com/cb', 'e2e-challenge', 'S256', $6)`,
			codeID, "e2e-code-hash-"+suffix, userID, org.ID, sessionID, time.Now().Add(5*time.Minute)); err != nil {
			t.Fatalf("seed auth code: %v", err)
		}

		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DELETE FROM oauth_authorization_codes WHERE user_id = $1", userID)
			_, _ = pool.Exec(context.Background(), "DELETE FROM oauth_refresh_tokens WHERE subject = $1", userID.String())
			_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
		})

		return seededCreds{orgID: org.ID, userID: userID, sessionID: sessionID, refreshID: refreshID, state: state, codeID: codeID}
	}

	// ── Assertion helpers ───────────────────────────────────────────────────
	sessionRevoked := func(t *testing.T, sid uuid.UUID) bool {
		t.Helper()
		var isValid bool
		var revokedAt *time.Time
		var reason *string
		if err := pool.QueryRow(ctx,
			`SELECT is_valid, revoked_at, revoked_reason FROM sessions WHERE id = $1`, sid).
			Scan(&isValid, &revokedAt, &reason); err != nil {
			t.Fatalf("read session: %v", err)
		}
		if isValid || revokedAt == nil {
			return false
		}
		if reason == nil || *reason != "organization_deleted" {
			t.Fatalf("session revoked but reason=%v (want organization_deleted)", reason)
		}
		return true
	}
	refreshRevoked := func(t *testing.T, rid uuid.UUID) bool {
		t.Helper()
		var revokedAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT revoked_at FROM oauth_refresh_tokens WHERE id = $1`, rid).Scan(&revokedAt); err != nil {
			t.Fatalf("read refresh token: %v", err)
		}
		return revokedAt != nil
	}
	oidcStateGone := func(t *testing.T, state string) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM oidc_states WHERE state = $1`, state).Scan(&n); err != nil {
			t.Fatalf("count oidc_states: %v", err)
		}
		return n == 0
	}
	authCodeConsumed := func(t *testing.T, cid uuid.UUID) bool {
		t.Helper()
		var consumedAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT consumed_at FROM oauth_authorization_codes WHERE id = $1`, cid).Scan(&consumedAt); err != nil {
			t.Fatalf("read auth code: %v", err)
		}
		return consumedAt != nil
	}
	userSoftDeleted := func(t *testing.T, uid uuid.UUID) bool {
		t.Helper()
		var deletedAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT deleted_at FROM users WHERE id = $1`, uid).Scan(&deletedAt); err != nil {
			t.Fatalf("read user: %v", err)
		}
		return deletedAt != nil
	}

	// ── Primary teeth: Delete(A) revokes A, leaves B untouched ──────────────
	t.Run("delete_revokes_target_org_only", func(t *testing.T) {
		a := seedOrgWithCreds(t)
		b := seedOrgWithCreds(t)

		if err := repos.Organization.Delete(ctx, a.orgID); err != nil {
			t.Fatalf("Delete(A): %v", err)
		}

		// A: every long-lived credential revoked/burned, user soft-deleted.
		if !sessionRevoked(t, a.sessionID) {
			t.Fatalf("A session: MUST be revoked (is_valid=false + revoked_at set)")
		}
		if !refreshRevoked(t, a.refreshID) {
			t.Fatalf("A refresh token: MUST have revoked_at set")
		}
		if !oidcStateGone(t, a.state) {
			t.Fatalf("A oidc_state: MUST be deleted")
		}
		if !authCodeConsumed(t, a.codeID) {
			t.Fatalf("A auth code: MUST be consumed (consumed_at set)")
		}
		if !userSoftDeleted(t, a.userID) {
			t.Fatalf("A user: MUST be soft-deleted (existing cascade)")
		}

		// B: org-scoping — nothing under B may be touched.
		if sessionRevoked(t, b.sessionID) {
			t.Fatalf("B session: MUST remain valid (org-scoping breach)")
		}
		if refreshRevoked(t, b.refreshID) {
			t.Fatalf("B refresh token: MUST remain non-revoked (org-scoping breach)")
		}
		if oidcStateGone(t, b.state) {
			t.Fatalf("B oidc_state: MUST remain present (org-scoping breach)")
		}
		if authCodeConsumed(t, b.codeID) {
			t.Fatalf("B auth code: MUST remain unconsumed (org-scoping breach)")
		}
		if userSoftDeleted(t, b.userID) {
			t.Fatalf("B user: MUST remain live (org-scoping breach)")
		}
	})

	// ── Idempotency: a second Delete returns ErrOrganizationNotFound ────────
	t.Run("second_delete_is_not_found", func(t *testing.T) {
		a := seedOrgWithCreds(t)
		if err := repos.Organization.Delete(ctx, a.orgID); err != nil {
			t.Fatalf("Delete(A) #1: %v", err)
		}
		if err := repos.Organization.Delete(ctx, a.orgID); err != domain.ErrOrganizationNotFound {
			t.Fatalf("Delete(A) #2: want ErrOrganizationNotFound, got %v", err)
		}
	})

	// ── Atomicity: an injected mid-tx failure rolls back the credential
	// revocation. A BEFORE DELETE trigger on oidc_states raises, so the
	// DELETE FROM oidc_states inside Delete's tx errors AFTER the session +
	// refresh revokes have executed — proving they roll back with it.
	t.Run("injected_failure_rolls_back_all", func(t *testing.T) {
		c := seedOrgWithCreds(t)

		if _, err := pool.Exec(ctx,
			`CREATE OR REPLACE FUNCTION e2e_p03b_fail() RETURNS trigger AS $$
			 BEGIN RAISE EXCEPTION 'e2e injected failure'; END; $$ LANGUAGE plpgsql`); err != nil {
			t.Fatalf("create trigger fn: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`CREATE TRIGGER e2e_p03b_fail_trg BEFORE DELETE ON oidc_states
			 FOR EACH ROW EXECUTE FUNCTION e2e_p03b_fail()`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS e2e_p03b_fail_trg ON oidc_states")
			_, _ = pool.Exec(context.Background(), "DROP FUNCTION IF EXISTS e2e_p03b_fail()")
		})

		if err := repos.Organization.Delete(ctx, c.orgID); err == nil {
			t.Fatalf("Delete(C): expected injected failure, got nil")
		}

		// The tx rolled back: the session + refresh revokes must NOT persist,
		// and the org itself must still be live.
		if sessionRevoked(t, c.sessionID) {
			t.Fatalf("atomicity breach: C session revoked despite tx rollback")
		}
		if refreshRevoked(t, c.refreshID) {
			t.Fatalf("atomicity breach: C refresh token revoked despite tx rollback")
		}
		if userSoftDeleted(t, c.userID) {
			t.Fatalf("atomicity breach: C user soft-deleted despite tx rollback")
		}
		var deletedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT deleted_at FROM organizations WHERE id = $1`, c.orgID).Scan(&deletedAt); err != nil {
			t.Fatalf("read org: %v", err)
		}
		if deletedAt != nil {
			t.Fatalf("atomicity breach: C org soft-deleted despite tx rollback")
		}
	})
}
