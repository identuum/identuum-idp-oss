package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

type recordingScopeTemplateRepo struct {
	repository.ScopeTemplateRepository
	stored      domain.ScopeTemplate
	updateCalls int
	last        *domain.ScopeTemplate
}

func (r *recordingScopeTemplateRepo) GetByID(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*domain.ScopeTemplate, error) {
	c := r.stored
	return &c, nil
}

func (r *recordingScopeTemplateRepo) Update(_ context.Context, t *domain.ScopeTemplate) error {
	r.updateCalls++
	r.last = t
	return nil
}

// THE-SILENT-DROP (2026-08-31): UpdateScopeTemplateOptions held plain strings
// compared against "", so PUT {"name":""} was MEASURED answering 200 with an
// unchanged row — a rename reported as a success that never happened. Worse,
// PUT {"name":"   "} answered 200 and STORED "   " as the template name,
// because ScopeTemplate.Validate checked `== ""` and whitespace slipped past
// the required-field rule entirely.
//
// RULE: SCOPE-TEMPLATE-UPDATE-BLANK-1
func TestScopeTemplateUpdate_BlankNameIsRefusedNotDroppedOrStored(t *testing.T) {
	orgID := uuid.New()
	tplID := uuid.New()

	newFixture := func() (*recordingScopeTemplateRepo, *ScopeTemplateService) {
		repo := &recordingScopeTemplateRepo{stored: domain.ScopeTemplate{
			ID: tplID, OrganizationID: orgID, Name: "Reader", Description: "read scopes",
			Scopes: []string{"read:things"},
		}}
		return repo, NewScopeTemplateService(nil, repo)
	}

	for _, blank := range []struct {
		why   string
		value string
	}{
		{"supplied empty — was DROPPED and answered 200", ""},
		{"whitespace only — was STORED as the name", "   "},
		{"a single tab", "\t"},
	} {
		repo, svc := newFixture()
		got, err := svc.Update(context.Background(), tplID, orgID, UpdateScopeTemplateOptions{Name: &blank.value})
		if err == nil {
			t.Errorf("a blank name (%s) was ACCEPTED", blank.why)
			if got != nil {
				t.Errorf("  the template now has name %q", got.Name)
			}
		}
		if repo.updateCalls != 0 {
			t.Errorf("a blank name (%s) still reached the repository %d time(s)", blank.why, repo.updateCalls)
		}
	}

	// ── a real rename still lands ──
	repo, svc := newFixture()
	renamed := "Reader v2"
	if _, err := svc.Update(context.Background(), tplID, orgID, UpdateScopeTemplateOptions{Name: &renamed}); err != nil {
		t.Fatalf("a real rename was rejected: %v", err)
	}
	if repo.updateCalls != 1 || repo.last == nil || repo.last.Name != "Reader v2" {
		t.Fatalf("the rename did not reach the repository intact (calls=%d)", repo.updateCalls)
	}

	// ── ABSENT leaves the name alone ──
	repo, svc = newFixture()
	if _, err := svc.Update(context.Background(), tplID, orgID, UpdateScopeTemplateOptions{
		Scopes: []string{"read:other"},
	}); err != nil {
		t.Fatalf("a scopes-only update was rejected: %v", err)
	}
	if repo.last == nil || repo.last.Name != "Reader" {
		t.Errorf("an absent name changed the stored name")
	}

	// ── a supplied empty DESCRIPTION clears it; the plain-string form could
	// not express a clear at all ──
	repo, svc = newFixture()
	empty := ""
	if _, err := svc.Update(context.Background(), tplID, orgID, UpdateScopeTemplateOptions{Description: &empty}); err != nil {
		t.Fatalf("clearing the description was rejected: %v", err)
	}
	if repo.last == nil || repo.last.Description != "" {
		t.Errorf("a supplied empty description did not clear it — the silent keep is back")
	}
}
