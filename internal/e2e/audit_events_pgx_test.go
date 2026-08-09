//go:build integration

// Package e2e — L-2: the OSS plain persistent audit log. These pins run
// against real Postgres so the audit_events INSERT (NULL mapping) and the
// retention DELETE are exercised end to end.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/... -run AuditEvents
//
// Safety: no secret/hash/DB URL is echoed. Rows are cleaned up on exit, and
// every event_type is suffixed with a per-run UUID so the assertions never
// collide with a prior run's residue.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_AuditEvents(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	// Cleanup DELETE must run BEFORE the pool closes. defers are LIFO, so
	// registering the delete AFTER pool.Close means it fires FIRST.
	defer pool.Close()

	// Per-run tag: every event_type this test writes ends with it, so a prior
	// run's rows can never satisfy or break these assertions.
	tag := "e2e." + uuid.NewString()[:8] + "."
	defer func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM audit_events WHERE event_type LIKE $1", tag+"%")
	}()

	countType := func(t *testing.T, eventType string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE event_type = $1", eventType).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", eventType, err)
		}
		return n
	}

	// ── Insert round-trip through the persistent service, with NULL mapping ──
	t.Run("record_persists_with_null_mapping", func(t *testing.T) {
		// repos.Audit satisfies the persistent service's inserter seam; the
		// wired type must NOT be NoopService (the "no longer Noop once wired"
		// guarantee, proven against the real repo the runtime uses).
		repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
		svc := service.NewPersistentAuditService(repos.Audit)
		if _, isNoop := any(svc).(audit.NoopService); isNoop {
			t.Fatal("persistent audit service must not be NoopService")
		}

		et := tag + "login.success"
		if err := svc.Record(ctx, audit.Event{
			Action:    et,
			ActorType: "user",
			ActorID:   uuid.New(),
			IPAddress: "203.0.113.4",
			Outcome:   "denied", // the success/denied discriminator round-trips
			// OrganizationID/SubjectID/emails left zero -> NULL columns
			Metadata: map[string]any{"k": "v"},
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}

		var actorType string
		var actorOrg *uuid.UUID
		var subjectEmail *string
		var ip *string
		var priority string
		var outcome *string
		if err := pool.QueryRow(ctx,
			`SELECT actor_type, actor_organization_id, subject_email, host(ip_address), priority, outcome
			   FROM audit_events WHERE event_type = $1`, et).
			Scan(&actorType, &actorOrg, &subjectEmail, &ip, &priority, &outcome); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if actorType != "user" || priority != "normal" {
			t.Fatalf("value columns: actor_type=%q priority=%q", actorType, priority)
		}
		if actorOrg != nil || subjectEmail != nil {
			t.Fatalf("zero inputs must be NULL: org=%v subjectEmail=%v", actorOrg, subjectEmail)
		}
		if ip == nil || *ip != "203.0.113.4" {
			t.Fatalf("ip_address round-trip: %v", ip)
		}
		if outcome == nil || *outcome != "denied" {
			t.Fatalf("outcome round-trip: %v", outcome)
		}

		// An emitter that supplies no outcome stores NULL.
		etNoOut := tag + "logout.noout"
		if err := svc.Record(ctx, audit.Event{Action: etNoOut, ActorType: "user"}); err != nil {
			t.Fatalf("Record no-outcome: %v", err)
		}
		var outcome2 *string
		if err := pool.QueryRow(ctx, "SELECT outcome FROM audit_events WHERE event_type = $1", etNoOut).Scan(&outcome2); err != nil {
			t.Fatalf("read no-outcome: %v", err)
		}
		if outcome2 != nil {
			t.Fatalf("empty outcome must be NULL, got %v", *outcome2)
		}
	})

	// ── Retention: rows older than the window die, newer survive ────────────
	t.Run("retention_prunes_old_keeps_new", func(t *testing.T) {
		repo := postgres.NewPgxAuditRepository(pool, 24*time.Hour)
		oldType := tag + "retention.old"
		newType := tag + "retention.new"

		if err := repo.Insert(ctx, auditEventAt(oldType, time.Now().UTC().Add(-48*time.Hour))); err != nil {
			t.Fatalf("insert old: %v", err)
		}
		if err := repo.Insert(ctx, auditEventAt(newType, time.Now().UTC())); err != nil {
			t.Fatalf("insert new: %v", err)
		}

		n, err := repo.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if n < 1 {
			t.Fatalf("expected at least the 48h-old row pruned, got %d", n)
		}
		if countType(t, oldType) != 0 {
			t.Fatal("48h-old row must be pruned by a 24h window")
		}
		if countType(t, newType) != 1 {
			t.Fatal("fresh row must survive")
		}
	})

	// ── Non-positive retention disables pruning, never writes ───────────────
	t.Run("non_positive_retention_disables_prune", func(t *testing.T) {
		repo := postgres.NewPgxAuditRepository(pool, 0)
		et := tag + "noprune.row"
		if err := repo.Insert(ctx, auditEventAt(et, time.Now().UTC().Add(-1000*time.Hour))); err != nil {
			t.Fatalf("insert: %v", err)
		}
		n, err := repo.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if n != 0 {
			t.Fatalf("retention<=0 must prune nothing, deleted %d", n)
		}
		if countType(t, et) != 1 {
			t.Fatal("row must survive when pruning is disabled")
		}
	})
}

// auditEventAt builds a minimal domain.AuditEvent with an explicit created_at
// so the retention boundary is deterministic.
func auditEventAt(eventType string, at time.Time) domain.AuditEvent {
	return domain.AuditEvent{
		ID:        uuid.New(),
		CreatedAt: at,
		EventType: domain.AuditEventType(eventType),
		ActorType: "system",
		Priority:  domain.AuditPriorityNormal,
	}
}
