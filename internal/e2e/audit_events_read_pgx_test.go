//go:build integration

// Package e2e — L-2 READ half: the PgxAuditRepository.ListEvents tenant clamp,
// filters and pagination run against real Postgres so the SQL org boundary
// (P3-13) and the has_more/limit policy are exercised end to end.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestE2E_OSS_AuditEvents_Read(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	repo := postgres.NewPgxAuditRepository(pool, time.Hour)

	tag := "e2eR." + uuid.NewString()[:8] + "."
	defer func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM audit_events WHERE event_type LIKE $1", tag+"%")
	}()

	// Two real orgs (audit_events.actor_organization_id FK -> organizations).
	newOrg := func(t *testing.T) uuid.UUID {
		t.Helper()
		suffix := uuid.NewString()
		org, err := repos.Organization.Create(ctx, &domain.Organization{
			Name: "e2e-audit-" + suffix, Domain: "e2e-audit-" + suffix + ".invalid",
			OrgSlug: "e2e-a-" + suffix[:8], Active: true, MFAPolicy: "optional",
		})
		if err != nil {
			t.Fatalf("seed org: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID) })
		return org.ID
	}
	orgA := newOrg(t)
	orgB := newOrg(t)

	insert := func(t *testing.T, org uuid.UUID, et, outcome string) {
		t.Helper()
		oc := outcome
		ev := domain.AuditEvent{
			ID: uuid.New(), CreatedAt: time.Now().UTC(),
			EventType: domain.AuditEventType(tag + et), ActorType: "user",
			ActorOrganizationID: &org, Priority: domain.AuditPriorityNormal,
		}
		if outcome != "" {
			ev.Outcome = &oc
		}
		if err := repo.Insert(ctx, ev); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert(t, orgA, "login", "success")
	insert(t, orgA, "login", "denied")
	insert(t, orgB, "login", "success")

	fresh := func() domain.AuditFilters {
		et := domain.AuditEventType(tag + "login")
		return domain.AuditFilters{EventType: &et}
	}

	// TENANT CLAMP: org A scope returns ONLY A's two rows, never B's.
	t.Run("org_scope_isolates", func(t *testing.T) {
		evs, hasMore, err := repo.ListEvents(ctx, &orgA, fresh())
		if err != nil {
			t.Fatalf("ListEvents A: %v", err)
		}
		if len(evs) != 2 || hasMore {
			t.Fatalf("org A: got %d rows hasMore=%v, want 2/false", len(evs), hasMore)
		}
		for _, e := range evs {
			if e.ActorOrganizationID == nil || *e.ActorOrganizationID != orgA {
				t.Fatalf("org A scope leaked a non-A row: %v", e.ActorOrganizationID)
			}
		}
	})

	// site_admin (nil scope) sees BOTH orgs' rows.
	t.Run("nil_scope_sees_all", func(t *testing.T) {
		evs, _, err := repo.ListEvents(ctx, nil, fresh())
		if err != nil {
			t.Fatalf("ListEvents nil: %v", err)
		}
		if len(evs) != 3 {
			t.Fatalf("unscoped: got %d rows, want 3 (both orgs)", len(evs))
		}
	})

	// outcome filter + round-trip; NULL outcome never matches a value filter.
	t.Run("outcome_filter", func(t *testing.T) {
		denied := "denied"
		f := fresh()
		f.Outcome = &denied
		evs, _, err := repo.ListEvents(ctx, &orgA, f)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		if len(evs) != 1 || evs[0].Outcome == nil || *evs[0].Outcome != "denied" {
			t.Fatalf("outcome=denied under org A: got %d rows", len(evs))
		}
	})

	// Pagination: limit=1 returns 1 row + has_more, newest first.
	t.Run("limit_and_has_more", func(t *testing.T) {
		f := fresh()
		f.Limit = 1
		evs, hasMore, err := repo.ListEvents(ctx, &orgA, f)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		if len(evs) != 1 || !hasMore {
			t.Fatalf("limit=1: got %d rows hasMore=%v, want 1/true", len(evs), hasMore)
		}
	})

	// A limit above the cap returns at most the cap (never unbounded).
	t.Run("limit_above_cap_bounded", func(t *testing.T) {
		f := fresh()
		f.Limit = 1_000_000
		evs, _, err := repo.ListEvents(ctx, &orgA, f)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		if len(evs) > postgres.AuditListMaxLimit {
			t.Fatalf("limit above cap returned %d rows, must be <= %d", len(evs), postgres.AuditListMaxLimit)
		}
	})

	// TEETH (mandatory): stable pagination under an IDENTICAL created_at.
	// Three rows in ONE org share the SAME timestamp; the id-DESC tiebreaker
	// (ORDER BY created_at DESC, id DESC) must give a strict total order, so
	// offset paging one-at-a-time yields three DISTINCT ids covering all
	// three with no repeat and no skip. Without the tiebreaker Postgres'
	// order over tied rows is UNSPECIFIED — it may happen to be stable.
	t.Run("stable_pagination_on_identical_created_at", func(t *testing.T) {
		orgC := newOrg(t)
		ts := time.Now().UTC().Truncate(time.Microsecond)
		ids := make(map[uuid.UUID]bool, 3)
		for i := 0; i < 3; i++ {
			id := uuid.New()
			ids[id] = true
			oc := orgC
			if err := repo.Insert(ctx, domain.AuditEvent{
				ID: id, CreatedAt: ts,
				EventType: domain.AuditEventType(tag + "tie"), ActorType: "user",
				ActorOrganizationID: &oc, Priority: domain.AuditPriorityNormal,
			}); err != nil {
				t.Fatalf("insert tie row: %v", err)
			}
		}
		tieType := domain.AuditEventType(tag + "tie")
		tieFilters := func() domain.AuditFilters { return domain.AuditFilters{EventType: &tieType} }

		// Full page: strict id-DESC over the identical timestamp.
		page, _, err := repo.ListEvents(ctx, &orgC, tieFilters())
		if err != nil {
			t.Fatalf("ListEvents page: %v", err)
		}
		if len(page) != 3 {
			t.Fatalf("tie page: got %d rows, want 3", len(page))
		}
		for i := 1; i < len(page); i++ {
			if !(page[i-1].ID.String() > page[i].ID.String()) {
				t.Fatalf("tie page not strict id-DESC at %d: %s then %s", i, page[i-1].ID, page[i].ID)
			}
		}

		// Offset paging 0,1,2 with limit=1 → three distinct ids covering all.
		seen := make(map[uuid.UUID]bool, 3)
		for off := 0; off < 3; off++ {
			f := tieFilters()
			f.Limit = 1
			f.Offset = off
			one, _, err := repo.ListEvents(ctx, &orgC, f)
			if err != nil {
				t.Fatalf("ListEvents offset %d: %v", off, err)
			}
			if len(one) != 1 {
				t.Fatalf("offset %d: got %d rows, want 1", off, len(one))
			}
			if seen[one[0].ID] {
				t.Fatalf("offset paging REPEATED id %s — unstable order", one[0].ID)
			}
			seen[one[0].ID] = true
		}
		if len(seen) != 3 {
			t.Fatalf("offset paging covered %d distinct ids, want all 3 (a skip occurred)", len(seen))
		}
		for id := range ids {
			if !seen[id] {
				t.Fatalf("offset paging SKIPPED seeded id %s", id)
			}
		}
	})

	// Newest-first: rows with DIFFERENT timestamps come back created_at-DESC.
	t.Run("newest_first_over_distinct_timestamps", func(t *testing.T) {
		orgD := newOrg(t)
		now := time.Now().UTC()
		od := orgD
		mk := func(et string, at time.Time) {
			if err := repo.Insert(ctx, domain.AuditEvent{
				ID: uuid.New(), CreatedAt: at,
				EventType: domain.AuditEventType(tag + et), ActorType: "user",
				ActorOrganizationID: &od, Priority: domain.AuditPriorityNormal,
			}); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		mk("t.old", now.Add(-2*time.Hour))
		mk("t.mid", now.Add(-1*time.Hour))
		mk("t.new", now)

		// orgD is fresh, so an unfiltered org scan returns exactly these three.
		evs, _, err := repo.ListEvents(ctx, &orgD, domain.AuditFilters{})
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		if len(evs) != 3 {
			t.Fatalf("got %d rows, want 3", len(evs))
		}
		for i := 1; i < len(evs); i++ {
			if evs[i-1].CreatedAt.Before(evs[i].CreatedAt) {
				t.Fatalf("not newest-first at %d: %v then %v", i, evs[i-1].CreatedAt, evs[i].CreatedAt)
			}
		}
		if evs[0].CreatedAt.Before(evs[2].CreatedAt) {
			t.Fatalf("first row is not the newest")
		}
	})
}
