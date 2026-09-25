package runtime

// OSS-SEC: the email verification service the RUNTIME builds must write its
// audit rows. Until this slice buildDeps constructed it with a nil audit
// service (the no-op), so a resend (mail sent) and a verify (a token burned)
// left no row at all. Driven through buildDeps against the test database:
// a resend and a verify for a seeded unverified user each leave one row,
// and neither row carries the address in clear.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

func auditRowsFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, event string, subject uuid.UUID) (rows int, clearAddress bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := pool.QueryRow(ctx, `
SELECT count(*),
       COALESCE(bool_or(COALESCE(subject_email, '') <> '' OR COALESCE(actor_email, '') <> '' OR metadata::text LIKE '%@%'), false)
  FROM audit_events WHERE event_type = $1 AND subject_id = $2`, event, subject).Scan(&rows, &clearAddress); err != nil {
			t.Fatalf("read audit_events: %v", err)
		}
		if rows > 0 || time.Now().After(deadline) {
			return rows, clearAddress
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestBuildDeps_EmailVerificationResendAndVerifyAreAudited(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "http://localhost",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	deps, pool, _, _, _, _, _, _, _, _, _, _, err := rt.buildDeps(ctx, lifecycle.NewStartupReport())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	defer pool.Close()
	if deps.EmailVerificationService == nil {
		t.Fatal("runtime did not wire the email verification service")
	}

	orgID, userID := uuid.New(), uuid.New()
	slug := "verify-" + uuid.NewString()[:8]
	email := slug + "@example.test"
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Verify "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified) VALUES ($1, $2, 'x', $3, 'org_user', false)`,
		userID, email, orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if err := deps.EmailVerificationService.ResendVerification(ctx, email); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if n, clear := auditRowsFor(t, ctx, pool, string(domain.AuditEmailVerificationResent), userID); n != 1 || clear {
		t.Fatalf("resend for an unverified user left %d %s row(s) (address in clear: %v); want 1, no address", n, domain.AuditEmailVerificationResent, clear)
	}

	raw := "verify-" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	if _, err := pool.Exec(ctx, `INSERT INTO email_verifications (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, NOW() + interval '1 hour', NOW())`,
		hex.EncodeToString(sum[:]), userID); err != nil {
		t.Fatalf("seed verification row: %v", err)
	}
	if err := deps.EmailVerificationService.VerifyEmail(ctx, raw, "203.0.113.40", "test-agent"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n, clear := auditRowsFor(t, ctx, pool, string(domain.AuditEmailVerified), userID); n != 1 || clear {
		t.Fatalf("verify left %d %s row(s) (address in clear: %v); want 1, no address", n, domain.AuditEmailVerified, clear)
	}
}
