package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// recordingOrgRoleRepo records what the service tried to persist. The
// embedded interface is nil on purpose — a method this test does not stub is
// one a REFUSED update must never reach.
type recordingOrgRoleRepo struct {
	repository.OrgRoleRepository
	stored      domain.OrgRole
	updateCalls int
	last        *domain.OrgRole
}

func (r *recordingOrgRoleRepo) GetByID(_ context.Context, _ uuid.UUID) (*domain.OrgRole, error) {
	c := r.stored
	return &c, nil
}

func (r *recordingOrgRoleRepo) Update(_ context.Context, role *domain.OrgRole) error {
	r.updateCalls++
	r.last = role
	return nil
}

// THE-SILENT-DROP (2026-08-31): UpdateRoleForActor ran NO validator. It read
//
//	if n := strings.TrimSpace(name); n != "" { role.Name = n }
//
// so PUT {"name":"   "} assigned nothing, wrote the unchanged row and
// answered 200 OK — the operator asked for a rename and was told it
// succeeded. The previous slice's inventory cleared this row as GUARDED on
// exactly that 200; a 200 that changes nothing is the defect, not the proof
// of absence.
//
// A plain string cannot express "supplied blank", so the options are now
// pointers: nil is absent, a supplied value is validated.
//
// RULE: ORG-ROLE-UPDATE-BLANK-1
func TestOrgRoleUpdate_BlankNameIsRefusedNotSilentlyDropped(t *testing.T) {
	orgID := uuid.New()
	roleID := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: orgID}

	newFixture := func() (*recordingOrgRoleRepo, *OrgRoleService) {
		repo := &recordingOrgRoleRepo{stored: domain.OrgRole{
			ID: roleID, OrgID: orgID, Name: "Auditor", Description: "reads audit logs",
		}}
		return repo, NewOrgRoleService(nil, repo, nil)
	}

	// ── THE DEFECT: a supplied blank name must be REFUSED, never dropped ──
	for _, blank := range []struct {
		why   string
		value string
	}{
		{"whitespace only — THE REPORTED DEFECT", "   "},
		{"a single tab", "\t"},
		{"supplied empty — a rename to nothing", ""},
	} {
		repo, svc := newFixture()
		got, err := svc.UpdateRoleForActor(context.Background(), actor, roleID, UpdateOrgRoleOptions{
			Name: &blank.value,
		})
		if err == nil {
			t.Errorf("a blank name (%s) was ACCEPTED — the rename was dropped and the caller told 200", blank.why)
			if got != nil && got.Name == "Auditor" {
				t.Errorf("  and the row came back UNCHANGED, which is exactly the lying success")
			}
		}
		if !errors.Is(err, errOrgRoleInvalid) {
			t.Errorf("a blank name (%s) refused with %v, not the ErrOrgRoleInvalid sentinel — the handler would not answer 400", blank.why, err)
		}
		if repo.updateCalls != 0 {
			t.Errorf("a blank name (%s) still reached the repository %d time(s)", blank.why, repo.updateCalls)
		}
	}

	// ── a real rename still lands, and is trimmed exactly as create trims ──
	repo, svc := newFixture()
	renamed := "  Security Auditor  "
	got, err := svc.UpdateRoleForActor(context.Background(), actor, roleID, UpdateOrgRoleOptions{Name: &renamed})
	if err != nil {
		t.Fatalf("a real rename was rejected: %v", err)
	}
	if repo.updateCalls != 1 {
		t.Fatalf("repository update calls = %d, want 1", repo.updateCalls)
	}
	if got.Name != "Security Auditor" {
		t.Fatalf("the rename stored %q; create trims, so update must trim identically", got.Name)
	}

	// ── ABSENT is still absent: nil leaves the field alone ──
	_, svc = newFixture()
	desc := "now with detail"
	got, err = svc.UpdateRoleForActor(context.Background(), actor, roleID, UpdateOrgRoleOptions{Description: &desc})
	if err != nil {
		t.Fatalf("a description-only update was rejected: %v", err)
	}
	if got.Name != "Auditor" {
		t.Errorf("an absent name changed the stored name to %q", got.Name)
	}
	if got.Description != "now with detail" {
		t.Errorf("the description did not apply: %q", got.Description)
	}

	// ── and a supplied empty DESCRIPTION now CLEARS it. The plain-string
	// form could not express this at all: a cleared description was
	// indistinguishable from an absent one, so it was silently kept. ──
	_, svc = newFixture()
	empty := ""
	got, err = svc.UpdateRoleForActor(context.Background(), actor, roleID, UpdateOrgRoleOptions{Description: &empty})
	if err != nil {
		t.Fatalf("clearing the description was rejected: %v", err)
	}
	if got.Description != "" {
		t.Errorf("a supplied empty description did not clear it (still %q) — the silent keep is back", got.Description)
	}
}
