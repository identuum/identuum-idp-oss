//go:build integration

// Package e2e — OSS-0914-STAGE-3 item 2 (follow-up of owner decision
// EMAIL-SCOPE (a), 2026-10-13): the database refuses an address another live
// account holds (migration 0056) also where the writer's own pre-check does
// not see that account. Self-registration with an address held by a banned
// account or by an account of an inactive organization takes the
// existing-address path, as an address the pre-check sees does; the restore
// of a deleted user whose address another live account now holds answers
// 409 email_exists. Proved through the runtime on the test database.
//
// Addresses are fixtures under example.invalid; tokens and passwords are
// never printed.
package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// refusals counts the self-registration refusals recorded for org.
func (w *inviteWorld) refusals(org uuid.UUID) int {
	w.t.Helper()
	var n int
	if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'user.self_registration_refused' AND organization_id = $1`, org).Scan(&n); err != nil {
		w.t.Fatalf("count refusals: %v", err)
	}
	return n
}

// registrationRefusal waits for a self-registration refusal of org beyond
// the before refusals already recorded and returns the newest one's reason.
func (w *inviteWorld) registrationRefusal(org uuid.UUID, before int) string {
	w.t.Helper()
	for i := 0; i < 30; i++ {
		if w.refusals(org) > before {
			var reason string
			_ = w.pool.QueryRow(w.ctx, `SELECT coalesce(metadata->>'reason', '') FROM audit_events
				WHERE event_type = 'user.self_registration_refused' AND organization_id = $1
				ORDER BY created_at DESC LIMIT 1`, org).Scan(&reason)
			return reason
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "none recorded"
}

// RULE: EMAIL-SPECIFIC-ANSWERS-1
func TestE2E_OSS_EmailSpecificAnswers(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase})

	reg := postgres.NewPgRegistrationRepository(w.pool)
	if err := reg.SetInstanceEnabled(w.ctx, true); err != nil {
		t.Fatalf("open self-registration: %v", err)
	}
	if err := reg.UpdateOrgSettings(w.ctx, w.orgA.ID, domain.OrgRegistrationSettings{Allow: true}); err != nil {
		t.Fatalf("open organization A: %v", err)
	}
	t.Cleanup(func() { _ = reg.SetInstanceEnabled(w.ctx, false) })

	register := func(t *testing.T, addr string) string {
		t.Helper()
		before := w.refusals(w.orgA.ID)
		st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/register/"+w.orgA.OrgSlug, `{"email":"`+addr+`","password":"`+invitePassword+`","name":"R"}`)
		if st != http.StatusAccepted {
			t.Fatalf("register = %d; want 202", st)
		}
		return w.registrationRefusal(w.orgA.ID, before)
	}

	t.Run("registration_banned_holder", func(t *testing.T) {
		taken := w.takenIn(w.orgB.ID, "example.invalid")
		if _, err := w.pool.Exec(w.ctx, `UPDATE users SET banned = true WHERE lower(email) = $1`, taken); err != nil {
			t.Fatalf("ban the holder: %v", err)
		}
		if reason := register(t, strings.ToUpper(taken)); reason != "existing_email" || w.liveWithEmail(taken) != 1 {
			t.Errorf("registration refusal = %q, accounts %d; want existing_email, nothing created", reason, w.liveWithEmail(taken))
		}
	})

	t.Run("registration_inactive_organization_holder", func(t *testing.T) {
		org := seedTestOrganization(t, w.ctx, w.repos)
		taken := w.takenIn(org.ID, "example.invalid")
		if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET active = false WHERE id = $1`, org.ID); err != nil {
			t.Fatalf("deactivate the holder's organization: %v", err)
		}
		if reason := register(t, taken); reason != "existing_email" || w.liveWithEmail(taken) != 1 {
			t.Errorf("registration refusal = %q, accounts %d; want existing_email, nothing created", reason, w.liveWithEmail(taken))
		}
	})

	t.Run("registration_control_new_address", func(t *testing.T) {
		fresh := "reg-" + uuid.NewString()[:8] + "@example.invalid"
		if reason := register(t, fresh); reason != "none recorded" || w.liveWithEmail(fresh) != 1 {
			t.Errorf("registration of a new address: refusal %q, accounts %d; want none, one account", reason, w.liveWithEmail(fresh))
		}
	})

	restore := func(id uuid.UUID) (int, string) {
		st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+id.String()+"/restore", "")
		e, _ := m["error"].(string)
		return st, e
	}
	deleted := func(t *testing.T) (uuid.UUID, string) {
		t.Helper()
		email := w.takenIn(w.orgA.ID, "example.invalid")
		u, err := w.repos.User.FindUsersByEmail(w.ctx, email)
		if err != nil || len(u) != 1 {
			t.Fatalf("find the seeded user: %d %v", len(u), err)
		}
		if err := w.repos.User.Delete(w.ctx, u[0].ID, w.orgA.ID); err != nil {
			t.Fatalf("delete the seeded user: %v", err)
		}
		return u[0].ID, email
	}

	t.Run("restore_address_held_elsewhere", func(t *testing.T) {
		id, email := deleted(t)
		if _, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: w.orgB.ID, Email: strings.ToUpper(email),
			PasswordHash: "dm-" + uuid.NewString(), Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}); err != nil {
			t.Fatalf("seed the new holder: %v", err)
		}
		var deletedAt *time.Time
		st, e := restore(id)
		_ = w.pool.QueryRow(w.ctx, `SELECT deleted_at FROM users WHERE id = $1`, id).Scan(&deletedAt)
		if st != http.StatusConflict || e != "email_exists" || deletedAt == nil || w.liveWithEmail(email) != 1 {
			t.Errorf("restore = %d %q, still deleted %v, accounts %d; want 409 email_exists, the user stays deleted", st, e, deletedAt != nil, w.liveWithEmail(email))
		}
	})

	t.Run("restore_control_free_address", func(t *testing.T) {
		id, _ := deleted(t)
		if st, e := restore(id); st != http.StatusOK {
			t.Errorf("restore of a free address = %d %q; want 200", st, e)
		}
	})
}
