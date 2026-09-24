package setup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// v0.5.1: first-run setup with the domain field left empty. The wizard
// (identuum-ui src/app/setup/setup-wizard.tsx) documents the fallback as
// slug(name) + ".local"; v0.5.0 used the raw name, so any name with a space
// failed organization validation and /api/setup/complete answered 400.

func createdOrgDomain(t *testing.T, h *testHarness, name string) string {
	t.Helper()
	for _, o := range h.orgRepo.orgs {
		if o.Name == name {
			return o.Domain
		}
	}
	t.Fatalf("no organization named %q was created", name)
	return ""
}

func TestComplete_EmptyDomainDefaultsToSlugDotLocal(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	in := validCompleteInput(banner.SetupToken)
	in.OrganizationDomain = ""

	if _, err := h.svc.Complete(context.Background(), h.dataDir, in); err != nil {
		t.Fatalf("Complete with a spaced name and no domain: %v", err)
	}
	if got := createdOrgDomain(t, h, "Acme Corp"); got != "acme-corp.local" {
		t.Fatalf("created domain = %q; want %q", got, "acme-corp.local")
	}
}

func TestComplete_ExplicitDomainIsKept(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)

	if _, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := createdOrgDomain(t, h, "Acme Corp"); got != "acme.example" {
		t.Fatalf("created domain = %q; want the explicit %q", got, "acme.example")
	}
}

// A name with no letter or digit has no slug, so there is no default domain
// to fall back to: the refusal is ErrOrganizationDomainRequired (a 400 the
// handler names), never a validation failure deeper down.
func TestComplete_EmptyDomainWithAnUnsluggableNameIsRefused(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	in := validCompleteInput(banner.SetupToken)
	in.OrganizationName = "!!!"
	in.OrganizationDomain = ""

	_, err := h.svc.Complete(context.Background(), h.dataDir, in)
	if !errors.Is(err, ErrOrganizationDomainRequired) {
		t.Fatalf("Complete(%q, no domain) err = %v; want ErrOrganizationDomainRequired", in.OrganizationName, err)
	}
	if view, _ := h.svc.Status(context.Background()); view.SetupComplete {
		t.Fatal("setup must stay incomplete after the refusal")
	}
	for _, o := range h.orgRepo.orgs {
		if o.ID.String() != domain.SystemOrgID {
			t.Fatalf("no organization may be created; found %q", o.Name)
		}
	}
}

// The default and its refusal apply only when an organization is created: a
// resumed setup reuses the organization a partial run left, whatever the new
// input says, exactly as before.
func TestComplete_ResumeIgnoresAnUnsluggableNameWithNoDomain(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	preExistingID, _ := uuid.NewRandom()
	now := time.Now().UTC()
	h.orgRepo.orgs = append(h.orgRepo.orgs, &domain.Organization{
		ID:        preExistingID,
		Name:      "Pre-existing Org",
		Domain:    "preexisting.example",
		OrgSlug:   "preexisting-org",
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	in := validCompleteInput(banner.SetupToken)
	in.OrganizationName = "!!!"
	in.OrganizationDomain = ""

	out, err := h.svc.Complete(context.Background(), h.dataDir, in)
	if err != nil {
		t.Fatalf("Complete (resume): %v", err)
	}
	if out.OrganizationID != preExistingID {
		t.Fatalf("resume should reuse %v, got %v", preExistingID, out.OrganizationID)
	}
}
