package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }

// recordingOrgRepo is the minimum OrganizationRepository that lets the test
// see WHAT reached the repository — the wiring, not just the helper.
type recordingOrgRepo struct {
	updateCalls int
	lastOpts    repository.UpdateOrganizationOptions
}

func (r *recordingOrgRepo) Update(_ context.Context, _ uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.updateCalls++
	r.lastOpts = opts
	return &domain.Organization{ID: uuid.New(), Name: "recorded", Domain: "recorded.test"}, nil
}

func (r *recordingOrgRepo) Create(context.Context, *domain.Organization) (*domain.Organization, error) {
	return nil, nil
}

func (r *recordingOrgRepo) CreateWithAdmin(context.Context, *domain.Organization, *domain.User) (*domain.Organization, *domain.User, error) {
	return nil, nil, nil
}
func (r *recordingOrgRepo) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) {
	return nil, nil
}
func (r *recordingOrgRepo) GetByDomain(context.Context, string) (*domain.Organization, error) {
	return nil, nil
}
func (r *recordingOrgRepo) GetBySlug(context.Context, string) (*domain.Organization, error) {
	return nil, nil
}
func (r *recordingOrgRepo) Delete(context.Context, uuid.UUID) error   { return nil }
func (r *recordingOrgRepo) Undelete(context.Context, uuid.UUID) error { return nil }
func (r *recordingOrgRepo) List(context.Context, repository.OrganizationFilter, repository.Pagination, repository.Sort) ([]*domain.Organization, int, error) {
	return nil, 0, nil
}
func (r *recordingOrgRepo) CountUsers(context.Context, uuid.UUID) (int, error)    { return 0, nil }
func (r *recordingOrgRepo) CountSessions(context.Context, uuid.UUID) (int, error) { return 0, nil }
func (r *recordingOrgRepo) GetDetails(context.Context, uuid.UUID) (*domain.Organization, map[string]int, error) {
	return nil, nil, nil
}

// THE WIRING PROOF. The helper being correct is worthless if Update() does
// not call it — the first version of this test passed with the guard removed,
// which is precisely the hole this case closes.
//
// RULE: ORG-UPDATE-VALIDATION-1
func TestOrganizationServiceUpdate_RefusesMalformedBeforeReachingTheRepository(t *testing.T) {
	repo := &recordingOrgRepo{}
	svc := NewOrganizationService(nil, repo)
	id := uuid.New()

	// A malformed domain must never reach the repository.
	if _, err := svc.Update(context.Background(), id, UpdateOrganizationOptions{
		Domain: strPtr("lexus"),
	}); err == nil {
		t.Fatal("Service.Update ACCEPTED \"lexus\" — the update path is unguarded")
	}
	if repo.updateCalls != 0 {
		t.Fatalf("the repository was called %d time(s) with a malformed domain", repo.updateCalls)
	}

	// A well-formed one must arrive NORMALIZED, so two spellings cannot
	// become two rows.
	if _, err := svc.Update(context.Background(), id, UpdateOrganizationOptions{
		Domain: strPtr("  LEXUS.COM.  "),
		Name:   strPtr("  Acme  "),
	}); err != nil {
		t.Fatalf("Service.Update rejected a well-formed change: %v", err)
	}
	if repo.updateCalls != 1 {
		t.Fatalf("repository update calls = %d, want 1", repo.updateCalls)
	}
	if repo.lastOpts.Domain == nil || *repo.lastOpts.Domain != "lexus.com" {
		t.Fatalf("the repository received un-normalized domain %v", repo.lastOpts.Domain)
	}
	if repo.lastOpts.Name == nil || *repo.lastOpts.Name != "Acme" {
		t.Fatalf("the repository received un-normalized name %v", repo.lastOpts.Name)
	}
}

// THE-UNVALIDATED-UPDATE (2026-08-31): OrganizationService.Update called
// s.repo.Update directly and NEVER validated, so PUT {"domain":"lexus"}
// persisted a value the create path refuses — and the repository appended the
// raw string without even the lowercase/trim create applies, so "LEXUS.COM "
// and "lexus.com" could become two rows.
//
// This pins the UPDATE path's field rules. The WIRING is pinned by
// TestOrganizationServiceUpdate_RefusesMalformedBeforeReachingTheRepository
// below, which carries the rule tag.
func TestOrganizationUpdate_ValidatesAndNormalizesEverySuppliedField(t *testing.T) {
	// ── the reported defect, on the path that was still open ──
	if _, err := normalizeAndValidateUpdate(UpdateOrganizationOptions{
		Domain: strPtr("lexus"),
	}); err == nil {
		t.Fatal("update ACCEPTED domain \"lexus\" — the defect is open on the update path")
	}

	// ── the SAME grammar as create: every shape create refuses, update refuses ──
	for _, bad := range []string{
		"lexus", "localhost", ".com", "example.", "exa..mple.com", "-bad.com",
		"bad-.com", "example.c", "example.123", "192.168.1.1", "exam ple.com",
		"under_score.com", "münchen.de", strings.Repeat("a", 64) + ".com",
	} {
		if _, err := normalizeAndValidateUpdate(UpdateOrganizationOptions{Domain: strPtr(bad)}); err == nil {
			t.Errorf("update accepted malformed domain %q", bad)
		}
	}

	// ── NORMALIZATION, so a rename cannot fork the key space ──
	out, err := normalizeAndValidateUpdate(UpdateOrganizationOptions{
		Domain: strPtr("  LEXUS.COM.  "),
	})
	if err != nil {
		t.Fatalf("update rejected a well-formed domain needing normalization: %v", err)
	}
	if out.Domain == nil || *out.Domain != "lexus.com" {
		t.Fatalf("update did not normalize: got %v, want \"lexus.com\"", out.Domain)
	}
	// The input must not be mutated in place — the caller passes the copy on.
	nameIn := "  Acme  "
	out2, err := normalizeAndValidateUpdate(UpdateOrganizationOptions{Name: &nameIn})
	if err != nil {
		t.Fatalf("update rejected a trimmable name: %v", err)
	}
	if nameIn != "  Acme  " {
		t.Fatalf("update mutated the caller's value: %q", nameIn)
	}
	if out2.Name == nil || *out2.Name != "Acme" {
		t.Fatalf("update did not trim the name: %v", out2.Name)
	}

	// ── EVERY other mutable field, one bad value each ──
	tier := domain.Tier(99)
	badCases := []struct {
		field string
		opts  UpdateOrganizationOptions
	}{
		{"name: whitespace only", UpdateOrganizationOptions{Name: strPtr("   ")}},
		{"name: over 255", UpdateOrganizationOptions{Name: strPtr(strings.Repeat("n", 256))}},
		{"max_sessions_per_user: 0", UpdateOrganizationOptions{MaxSessionsPerUser: intPtr(0)}},
		{"max_sessions_per_user: 101", UpdateOrganizationOptions{MaxSessionsPerUser: intPtr(101)}},
		{"mfa_policy: unknown", UpdateOrganizationOptions{MFAPolicy: strPtr("sometimes")}},
		{"auth_policy: unknown", UpdateOrganizationOptions{AuthPolicy: strPtr("whenever")}},
		{"api_authorization_policy: unknown", UpdateOrganizationOptions{ApiAuthorizationPolicy: strPtr("LOOSE")}},
		{"service_account_expiry_days: negative", UpdateOrganizationOptions{ServiceAccountExpiryDays: intPtr(-1)}},
		{"service_account_expiry_days: over 3650", UpdateOrganizationOptions{ServiceAccountExpiryDays: intPtr(3651)}},
		{"m2m_anomaly_limit: negative", UpdateOrganizationOptions{M2MAnomalyLimit: intPtr(-1)}},
		{"m2m_anomaly_window_seconds: negative", UpdateOrganizationOptions{M2MAnomalyWindowSeconds: intPtr(-1)}},
		{"tier: outside the enum", UpdateOrganizationOptions{Tier: &tier}},
		{"compliance_contact_email: not an address", UpdateOrganizationOptions{ComplianceContactEmail: strPtr("not-an-email")}},
	}
	for _, c := range badCases {
		if _, err := normalizeAndValidateUpdate(c.opts); err == nil {
			t.Errorf("update accepted an invalid field — %s", c.field)
		}
	}

	// ── and the legitimate values must still pass ──
	okTier := domain.TierPro
	for _, c := range []struct {
		why  string
		opts UpdateOrganizationOptions
	}{
		{"an empty option set changes nothing", UpdateOrganizationOptions{}},
		{"a well-formed domain", UpdateOrganizationOptions{Domain: strPtr("saab.se")}},
		{"the system domain", UpdateOrganizationOptions{Domain: strPtr("system.local")}},
		{"a real name", UpdateOrganizationOptions{Name: strPtr("Acme Corp")}},
		{"clearing the compliance email", UpdateOrganizationOptions{ComplianceContactEmail: strPtr("")}},
		{"a valid compliance email", UpdateOrganizationOptions{ComplianceContactEmail: strPtr("ops@example.com")}},
		{"a listed tier", UpdateOrganizationOptions{Tier: &okTier}},
		{"zero m2m thresholds", UpdateOrganizationOptions{M2MAnomalyLimit: intPtr(0), M2MAnomalyWindowSeconds: intPtr(0)}},
	} {
		if _, err := normalizeAndValidateUpdate(c.opts); err != nil {
			t.Errorf("update rejected a legitimate change (%s): %v", c.why, err)
		}
	}
}
