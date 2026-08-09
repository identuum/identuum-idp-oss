package domain_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE R-SUITE — AdminPermissionsModel.md, one executable test per rule, named
// by its matrix id so a failure says WHICH rule broke.
//
// The rules this file covers are the ones expressible as pure invariants over
// domain constants. The behavioural rules (R9-R21) live beside the code that
// enforces them — internal/service/model_sentinel_guards_test.go,
// internal/handlers/model_404_test.go, internal/service/site_admin_tenant_write_test.go
// — and the DATABASE-level teeth are pinned by migration 0027 and exercised in
// internal/e2e. This file is the part that needs no wiring at all, so it can
// never be skipped for want of a database.

// R4 — "System organization has lowest possible UUIDv7 id."
func TestR4_SystemOrgIDIsLowestUUIDv7(t *testing.T) {
	const want = "00000000-0000-7000-0000-000000000000"
	if domain.SystemOrgID != want {
		t.Fatalf("SystemOrgID = %q, want %q", domain.SystemOrgID, want)
	}
	id, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		t.Fatalf("SystemOrgID does not parse: %v", err)
	}
	if id.Version() != 7 {
		t.Errorf("SystemOrgID version = %d, want 7 — the model says UUIDv7", id.Version())
	}
	if id == uuid.Nil {
		t.Error("SystemOrgID is the nil UUID; the model's value is version-7 zero, not nil")
	}
}

// R5 — "site_admin user has lowest possible UUIDv7 id. (…0001)"
func TestR5_SiteAdminIDIsLowestUUIDv7Plus1(t *testing.T) {
	const want = "00000000-0000-7000-0000-000000000001"
	if domain.SiteAdminID != want {
		t.Fatalf("SiteAdminID = %q, want %q", domain.SiteAdminID, want)
	}
	id, err := uuid.Parse(domain.SiteAdminID)
	if err != nil {
		t.Fatalf("SiteAdminID does not parse: %v", err)
	}
	if id.Version() != 7 {
		t.Errorf("SiteAdminID version = %d, want 7", id.Version())
	}
	if domain.SiteAdminID == domain.SystemOrgID {
		t.Fatal("the site_admin and the System organization share one id")
	}
}

// R6 — "user id is site_admin@system.local"
func TestR6_SiteAdminLoginIdentifier(t *testing.T) {
	const want = "site_admin@system.local"
	if domain.SiteAdminEmail != want {
		t.Fatalf("SiteAdminEmail = %q, want %q — this is the LOGIN identifier, "+
			"distinct from the contact-email field the installer sets", domain.SiteAdminEmail, want)
	}
}

// R8 — 'System Organization name is "System Organization", slug is: system-local'
func TestR8_SystemOrgNameAndSlug(t *testing.T) {
	if domain.SystemOrgName != "System Organization" {
		t.Errorf("SystemOrgName = %q, want %q", domain.SystemOrgName, "System Organization")
	}
	if domain.SystemOrgSlug != "system-local" {
		t.Errorf("SystemOrgSlug = %q, want %q", domain.SystemOrgSlug, "system-local")
	}
}

// R1 — "These rules MUST be exact same in both identuum-idp-oss and
// identuum-idp-ce, it cannot vary between these products."
//
// The cross-product half cannot be asserted from inside one module — CE has no
// import path here. What IS asserted is the contract each side must satisfy:
// the four pinned values, spelled out as literals so the CE twin
// (internal/commercial/org/r_suite_test.go) can assert the SAME literals. If
// either side moves, its own R-suite goes red.
func TestR1_PinnedValuesAreTheSharedContract(t *testing.T) {
	shared := map[string]string{
		"SystemOrgID":    "00000000-0000-7000-0000-000000000000",
		"SiteAdminID":    "00000000-0000-7000-0000-000000000001",
		"SiteAdminEmail": "site_admin@system.local",
		"SystemOrgName":  "System Organization",
		"SystemOrgSlug":  "system-local",
	}
	got := map[string]string{
		"SystemOrgID":    domain.SystemOrgID,
		"SiteAdminID":    domain.SiteAdminID,
		"SiteAdminEmail": domain.SiteAdminEmail,
		"SystemOrgName":  domain.SystemOrgName,
		"SystemOrgSlug":  domain.SystemOrgSlug,
	}
	for k, want := range shared {
		if got[k] != want {
			t.Errorf("%s = %q, want %q — identuum-idp-ce pins the same literal; a change here "+
				"without the same change there is a rule-one divergence", k, got[k], want)
		}
	}
}

// R21 — "Org User: … No administrative authority of any kind."
// The scope derivation is the machine-readable form of that sentence.
func TestR21_OrgUserCarriesNoAdministrativeScopes(t *testing.T) {
	if s := domain.SessionScopesForRole(domain.RoleOrgUser); s != "" {
		t.Fatalf("an org_user session token carries scopes %q, want none — the model gives it "+
			"no administrative authority of any kind", s)
	}
	// CONTROL: the derivation is not simply empty for everyone.
	if s := domain.SessionScopesForRole(domain.RoleOrgAdmin); s == "" {
		t.Fatal("CONTROL FAILED: org_admin also derives no scopes, so the org_user assertion " +
			"above passes for the wrong reason")
	}
}

// R15/R16 — "Org Admin: … Manages exactly one organization -- their own -- and
// nothing outside it. Day-to-day control of that organization's resources
// (users, clients, service accounts, identity provider, protocol settings,
// domains, RBAC roles)."
func TestR16_OrgAdminScopeSetCoversTheGrantedAreas(t *testing.T) {
	held := map[string]bool{}
	for _, s := range domain.OrgAdminSessionScopes {
		held[s] = true
	}
	// One scope per area the model names by hand.
	for area, scope := range map[string]string{
		"users":             domain.ScopeUsersRead,
		"clients":           domain.ScopeClientsRead,
		"service accounts":  domain.ScopeM2MRead,
		"identity provider": domain.ScopeIDPsRead,
		"RBAC roles":        domain.ScopeOrgsRead,
	} {
		if !held[scope] {
			t.Errorf("the model grants org_admin %q but the session scope set omits %q", area, scope)
		}
	}
	// R20 — "cannot manage organization lifecycle (create/delete/activate --
	// infrastructure authority)."
	for _, forbidden := range []string{
		domain.ScopeOrgsCreate, domain.ScopeOrgsDelete, domain.ScopeOrgsDisable,
	} {
		if held[forbidden] {
			t.Errorf("org_admin holds %q — the model reserves organization lifecycle to "+
				"infrastructure authority", forbidden)
		}
	}
	// Every scope must be registered, or a typo grants nothing while reading
	// as a grant.
	for _, s := range domain.OrgAdminSessionScopes {
		if !domain.IsKnownScope(s) {
			t.Errorf("OrgAdminSessionScopes contains unregistered scope %q", s)
		}
	}
	if len(domain.OrgAdminSessionScopes) == 0 {
		t.Fatal("OrgAdminSessionScopes is empty")
	}
}

// R18 — "cannot promote anyone to site_admin."
func TestR18_SiteAdminIsNotAnAssignableOrgRole(t *testing.T) {
	// PREMISE FIRST. This test is a loop that reports nothing when the set is
	// empty, so without this line it passes green against zero scopes — proved
	// by emptying OrgAdminSessionScopes and watching it report
	// `--- PASS: TestR18_SiteAdminIsNotAnAssignableOrgRole` while asserting
	// nothing at all. An absence assertion needs a non-empty population or it
	// is a decoration.
	if len(domain.OrgAdminSessionScopes) == 0 {
		t.Fatal("PREMISE FAILED: OrgAdminSessionScopes is empty, so the loop below inspects " +
			"nothing and would report success without having looked at a single scope")
	}
	// And the scopes must be REAL, not just present: a set of unregistered
	// strings contains no "site" substring either, and would pass for the same
	// hollow reason.
	for _, s := range domain.OrgAdminSessionScopes {
		if !domain.IsKnownScope(s) {
			t.Fatalf("PREMISE FAILED: %q is not a registered scope, so this set is not the "+
				"thing the model grants org_admin", s)
		}
	}

	for _, s := range domain.OrgAdminSessionScopes {
		if strings.Contains(s, "site") {
			t.Errorf("org_admin holds a site-shaped scope %q", s)
		}
	}
}
