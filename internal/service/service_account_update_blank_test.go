package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-SILENT-DROP (2026-08-31): ServiceAccountService.UpdateForActor shared
// the create path's plain-string input, so PUT {"name":""} and
// PUT {"name":"   "} were BOTH MEASURED answering 200 with an unchanged row.
// The create path has refused a blank name since it was written; the update
// path could not even see that one had been supplied.
//
// Asserted THROUGH the service with the package's recording repository.
//
// RULE: SERVICE-ACCOUNT-UPDATE-BLANK-1
func TestServiceAccountUpdate_BlankNameIsRefusedNotSilentlyDropped(t *testing.T) {
	orgID := uuid.New()
	saID := uuid.New()
	actor := newOrgAdmin(orgID)

	newFixture := func() (*adminFakeSARepo, *ServiceAccountService) {
		svc, repo := newAdminSAService()
		repo.byID[saID] = &domain.ServiceAccount{
			ID: saID, OrganizationID: orgID, Active: true,
			Role: domain.RoleOrgUser, Name: "ci", Description: "build runner",
		}
		return repo, svc
	}

	for _, blank := range []struct {
		why   string
		value string
	}{
		{"supplied empty", ""},
		{"whitespace only", "   "},
		{"a single tab", "\t"},
	} {
		repo, svc := newFixture()
		got, err := svc.UpdateForActor(context.Background(), actor, saID, ServiceAccountUpdateInput{
			Name: &blank.value,
		})
		if err == nil {
			t.Errorf("a blank name (%s) was ACCEPTED — the rename was dropped and the caller told 200", blank.why)
		}
		if !errors.Is(err, ErrSAInvalidInput) {
			t.Errorf("a blank name (%s) refused with %v, want ErrSAInvalidInput", blank.why, err)
		}
		if got != nil {
			t.Errorf("a refused update still returned a service account")
		}
		if stored := repo.byID[saID]; stored != nil && stored.Name != "ci" {
			t.Errorf("a refused update changed the stored name to %q", stored.Name)
		}
	}

	// ── a real rename still lands, trimmed as create trims ──
	_, svc := newFixture()
	renamed := "  ci-v2  "
	got, err := svc.UpdateForActor(context.Background(), actor, saID, ServiceAccountUpdateInput{Name: &renamed})
	if err != nil {
		t.Fatalf("a real rename was rejected: %v", err)
	}
	if got.Name != "ci-v2" {
		t.Fatalf("the rename stored %q; create trims, so update must trim identically", got.Name)
	}

	// ── ABSENT leaves the name alone ──
	_, svc = newFixture()
	newRole := domain.RoleOrgAdmin
	got, err = svc.UpdateForActor(context.Background(), actor, saID, ServiceAccountUpdateInput{Role: &newRole})
	if err != nil {
		t.Fatalf("a role-only update was rejected: %v", err)
	}
	if got.Name != "ci" {
		t.Errorf("an absent name changed the stored name to %q", got.Name)
	}

	// ── a supplied empty DESCRIPTION clears it ──
	_, svc = newFixture()
	empty := ""
	got, err = svc.UpdateForActor(context.Background(), actor, saID, ServiceAccountUpdateInput{Description: &empty})
	if err != nil {
		t.Fatalf("clearing the description was rejected: %v", err)
	}
	if got.Description != "" {
		t.Errorf("a supplied empty description did not clear it (still %q)", got.Description)
	}
}
