package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Owner ruling (v0.9.5): an organization whose org_admin lost every factor
// gets it back through a one-shot operator command that needs host access
// (docker exec / docker run --entrypoint), never through the site_admin API
// (D-025).

type fakePasskeys struct {
	creds   []*domain.WebAuthnCredential
	deleted []uuid.UUID
}

func (f *fakePasskeys) ListByUser(_ context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	var out []*domain.WebAuthnCredential
	for _, c := range f.creds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakePasskeys) Delete(_ context.Context, id uuid.UUID) error {
	f.deleted = append(f.deleted, id)
	return nil
}

type fakeSessionRevoker struct{ users []uuid.UUID }

func (f *fakeSessionRevoker) RevokeByUserID(_ context.Context, userID uuid.UUID, _ string) error {
	f.users = append(f.users, userID)
	return nil
}

type fakeRefreshRevoker struct{ subjects []string }

func (f *fakeRefreshRevoker) RevokeAllBySubject(_ context.Context, subject string, _ time.Time) (int64, error) {
	f.subjects = append(f.subjects, subject)
	return 2, nil
}

// auditRows keeps the rows the persistent audit service would insert.
type auditRows struct{ rows []domain.AuditEvent }

func (a *auditRows) Insert(_ context.Context, e domain.AuditEvent) error {
	a.rows = append(a.rows, e)
	return nil
}

type resetHarness struct {
	deps     resetOrgAdminMFADeps
	users    *memUserRepo
	passkeys *fakePasskeys
	sessions *fakeSessionRevoker
	refresh  *fakeRefreshRevoker
	rec      *auditRows
	org      uuid.UUID
	admin    *domain.User
	member   *domain.User
}

func newResetHarness(t *testing.T) resetHarness {
	t.Helper()
	org := uuid.New()
	secret := "SEED-MUST-NOT-SURVIVE"
	admin := &domain.User{ID: uuid.New(), OrganizationID: org, Email: "admin@acme.test", Role: domain.RoleOrgAdmin,
		MFAEnabled: true, MFASecret: &secret, MFARecoveryCodes: []string{"code"}}
	member := &domain.User{ID: uuid.New(), OrganizationID: org, Email: "member@acme.test", Role: domain.RoleOrgUser, MFAEnabled: true}
	h := resetHarness{
		users:    &memUserRepo{users: []*domain.User{admin, member}},
		passkeys: &fakePasskeys{creds: []*domain.WebAuthnCredential{{ID: uuid.New(), UserID: admin.ID}}},
		sessions: &fakeSessionRevoker{},
		refresh:  &fakeRefreshRevoker{},
		rec:      &auditRows{},
		org:      org,
		admin:    admin,
		member:   member,
	}
	h.deps = resetOrgAdminMFADeps{
		Users: h.users, Passkeys: h.passkeys, Sessions: h.sessions, Refresh: h.refresh, Audit: service.NewOperatorAuditor(h.rec),
		Now: func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) },
	}
	return h
}

func TestResetOrgAdminMFA_RemovesEveryFactorRevokesAndAudits(t *testing.T) {
	h := newResetHarness(t)
	var stdout, stderr bytes.Buffer
	if rc := resetOrgAdminMFACore(context.Background(), h.deps, h.org, "admin@acme.test", &stdout, &stderr); rc != 0 {
		t.Fatalf("rc = %d, stderr = %s", rc, stderr.String())
	}
	u := h.users.users[0]
	if u.MFAEnabled || (u.MFASecret != nil && *u.MFASecret != "") || len(u.MFARecoveryCodes) != 0 {
		t.Errorf("second factor not cleared: enabled=%t codes=%d", u.MFAEnabled, len(u.MFARecoveryCodes))
	}
	if len(h.passkeys.deleted) != 1 {
		t.Errorf("passkeys deleted = %d, want 1", len(h.passkeys.deleted))
	}
	if len(h.sessions.users) != 1 || h.sessions.users[0] != h.admin.ID {
		t.Errorf("sessions revoked for %v, want the org_admin", h.sessions.users)
	}
	if len(h.refresh.subjects) != 1 || h.refresh.subjects[0] != h.admin.ID.String() {
		t.Errorf("refresh tokens revoked for %v, want the org_admin", h.refresh.subjects)
	}
	if len(h.rec.rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(h.rec.rows))
	}
	e := h.rec.rows[0]
	if e.EventType != domain.AuditOrgAdminMFAReset || e.ActorType != "system" || e.OrganizationID == nil || *e.OrganizationID != h.org ||
		e.SubjectID == nil || *e.SubjectID != h.admin.ID || e.Metadata["via"] != "cli" || e.Metadata["refresh_tokens_revoked_count"] != int64(2) {
		t.Errorf("audit row = %+v, want org_admin_mfa_reset by the system actor via cli, 2 refresh tokens revoked", e)
	}
	if strings.Contains(stdout.String()+stderr.String(), "SEED-MUST-NOT-SURVIVE") {
		t.Error("the MFA secret reached the output")
	}
}

func TestResetOrgAdminMFA_RefusesWhatItIsNotFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		org   func(h resetHarness) uuid.UUID
		email string
	}{
		{"the system organization (recover-site-admin is its command)", func(resetHarness) uuid.UUID { return uuid.MustParse(domain.SystemOrgID) }, "admin@acme.test"},
		{"a user who is not an org_admin", func(h resetHarness) uuid.UUID { return h.org }, "member@acme.test"},
		{"an unknown address", func(h resetHarness) uuid.UUID { return h.org }, "nobody@acme.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newResetHarness(t)
			var stdout, stderr bytes.Buffer
			if rc := resetOrgAdminMFACore(context.Background(), h.deps, tc.org(h), tc.email, &stdout, &stderr); rc == 0 {
				t.Fatalf("rc = 0, want a refusal")
			}
			if !h.users.users[0].MFAEnabled || !h.users.users[1].MFAEnabled || len(h.passkeys.deleted) != 0 || len(h.sessions.users) != 0 || len(h.rec.rows) != 0 {
				t.Error("a refusal changed something")
			}
		})
	}
}

func TestDispatchResetOrgAdminMFA_NeedsOrgAndEmailBeforeAnyDatabase(t *testing.T) {
	for _, args := range [][]string{
		{"--email", "admin@acme.test"},
		{"--org", uuid.NewString()},
		{"--org", "not-a-uuid", "--email", "admin@acme.test"},
	} {
		var stdout, stderr bytes.Buffer
		if rc := dispatchResetOrgAdminMFA(context.Background(), args, &stdout, &stderr); rc != 2 {
			t.Errorf("args %v: rc = %d, want 2 (%s)", args, rc, stderr.String())
		}
	}
}
