package handlers

// ORG-ADMIN-STATE-1 — the organizations API's admin state reflects the
// live org_admin counts (PHANTOM-NO-ADMIN).
//
// The defect this fences: GET /api/v1/organizations and
// GET /api/v1/organizations/:id serialized `safeOrganization` WITHOUT
// is_claimed / can_assign_admin, while the UI mapped
// `has_admin = Boolean(o.is_claimed)` — Boolean(undefined) — so EVERY
// org rendered as "No active administrator" with an Assign affordance,
// even when an active verified org_admin existed. The correct
// computation lived only in dead code (mappers.ToOrganizationList).
//
// Pinned here, hermetically (no DB, no HTTP server):
//   1. list + get emit is_claimed = (live org_admin count > 0) and
//      can_assign_admin = (is_claimed && verified count == 0), per org,
//      from the wired counter — the live counts, not a stored flag.
//   2. the org_admin single-row list branch carries the same state.
//   3. an UNWIRED counter records a FATAL fault naming
//      organizations-admin-state AND the fields are ABSENT from the
//      JSON — never false. Absence must stay distinguishable from a
//      true "no admin" so the UI can render "status unavailable"
//      instead of a phantom "No administrator".
//   4. a counter ERROR at request time also emits ABSENT, never false,
//      and never fails the request.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// fakeOrgAdminCounter implements OrgAdminCounter with settable counts.
type fakeOrgAdminCounter struct {
	admins   map[uuid.UUID]int
	verified map[uuid.UUID]int
	err      error
}

func (f *fakeOrgAdminCounter) CountOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.admins, nil
}

func (f *fakeOrgAdminCounter) CountVerifiedOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.verified, nil
}

type adminStateEngine struct {
	r       *gin.Engine
	orgRepo *memOrgRepo
	report  *lifecycle.StartupReport
}

func newAdminStateEngine(t *testing.T, principal *domain.Principal, counter OrgAdminCounter) adminStateEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	orgRepo := newMemOrgRepo()
	report := lifecycle.NewStartupReport()
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		Audit:               &audit.Recorder{},
		StartupReport:       report,
		AdminCounter:        counter,
	})
	return adminStateEngine{r: r, orgRepo: orgRepo, report: report}
}

func seedAdminStateOrg(t *testing.T, eng adminStateEngine, name string) *domain.Organization {
	t.Helper()
	now := time.Now().UTC()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuidv7: %v", err)
	}
	o := &domain.Organization{
		ID:                 id,
		Name:               name,
		Domain:             strings.ToLower(name) + ".test",
		OrgSlug:            strings.ToLower(name),
		Active:             true,
		MaxSessionsPerUser: 10,
		MFAPolicy:          "optional",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if _, err := eng.orgRepo.Create(context.Background(), o); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return o
}

func adminStateDo(t *testing.T, eng adminStateEngine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// requireAdminState asserts the org JSON object carries BOTH admin-state
// keys with exactly the wanted boolean values.
func requireAdminState(t *testing.T, org map[string]any, wantClaimed, wantCanAssign bool) {
	t.Helper()
	claimed, ok := org["is_claimed"]
	if !ok {
		t.Fatalf("org %v: is_claimed ABSENT from payload, want %v", org["name"], wantClaimed)
	}
	if claimed != wantClaimed {
		t.Errorf("org %v: is_claimed = %v, want %v", org["name"], claimed, wantClaimed)
	}
	canAssign, ok := org["can_assign_admin"]
	if !ok {
		t.Fatalf("org %v: can_assign_admin ABSENT from payload, want %v", org["name"], wantCanAssign)
	}
	if canAssign != wantCanAssign {
		t.Errorf("org %v: can_assign_admin = %v, want %v", org["name"], canAssign, wantCanAssign)
	}
}

// requireAdminStateAbsent asserts NEITHER admin-state key is present —
// the unwired/error projection must be absence, never false.
func requireAdminStateAbsent(t *testing.T, org map[string]any) {
	t.Helper()
	if v, ok := org["is_claimed"]; ok {
		t.Errorf("org %v: is_claimed present (= %v), want ABSENT — absence must never collapse to false", org["name"], v)
	}
	if v, ok := org["can_assign_admin"]; ok {
		t.Errorf("org %v: can_assign_admin present (= %v), want ABSENT", org["name"], v)
	}
}

func decodeOrgList(t *testing.T, rec *httptest.ResponseRecorder) map[uuid.UUID]map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Organizations []map[string]any `json:"organizations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	out := make(map[uuid.UUID]map[string]any, len(body.Organizations))
	for _, o := range body.Organizations {
		id, err := uuid.Parse(o["id"].(string))
		if err != nil {
			t.Fatalf("org id: %v", err)
		}
		out[id] = o
	}
	return out
}

func decodeOrg(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var o map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatalf("decode org: %v", err)
	}
	return o
}

// TestOrgAdminState_ListAndGetReflectLiveCounts pins the projection
// formula on both read handlers across the three live states:
//   - steady (admins>0, verified>0)  → is_claimed=true,  can_assign_admin=false
//   - expired-pending (admins>0, verified=0) → true, true
//   - no admin (admins=0)            → false, false
//
// RULE: ORG-ADMIN-STATE-1
func TestOrgAdminState_ListAndGetReflectLiveCounts(t *testing.T) {
	counter := &fakeOrgAdminCounter{admins: map[uuid.UUID]int{}, verified: map[uuid.UUID]int{}}
	eng := newAdminStateEngine(t, siteAdminPrincipal(), counter)

	steady := seedAdminStateOrg(t, eng, "steady")
	expired := seedAdminStateOrg(t, eng, "expiredpending")
	orphan := seedAdminStateOrg(t, eng, "noadmin")

	counter.admins[steady.ID] = 2
	counter.verified[steady.ID] = 1
	counter.admins[expired.ID] = 1
	// expired: verified stays 0. orphan: both stay 0.

	if eng.report.HasFatal() {
		t.Fatalf("wired counter must not record a fault; faults=%+v", eng.report.Faults())
	}

	list := decodeOrgList(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations"))
	if len(list) != 3 {
		t.Fatalf("list returned %d orgs, want 3", len(list))
	}
	requireAdminState(t, list[steady.ID], true, false)
	requireAdminState(t, list[expired.ID], true, true)
	requireAdminState(t, list[orphan.ID], false, false)

	for _, tc := range []struct {
		org                 *domain.Organization
		claimed, wantAssign bool
	}{
		{steady, true, false},
		{expired, true, true},
		{orphan, false, false},
	} {
		got := decodeOrg(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations/"+tc.org.ID.String()))
		requireAdminState(t, got, tc.claimed, tc.wantAssign)
	}
	t.Logf("EVIDENCE admin-state: list+get emit live counts for steady/expired-pending/no-admin")
}

// TestOrgAdminState_OrgAdminSingleRowListCarriesState pins the org_admin
// branch of the list handler: the single-row own-org list carries the
// same live projection.
func TestOrgAdminState_OrgAdminSingleRowListCarriesState(t *testing.T) {
	counter := &fakeOrgAdminCounter{admins: map[uuid.UUID]int{}, verified: map[uuid.UUID]int{}}
	// Seed first with a throwaway engine-less repo? The engine needs the
	// principal bound to the org id — seed via a bootstrap engine sharing
	// the same repo is overkill; instead create the org id up front.
	orgID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuidv7: %v", err)
	}
	principal := &domain.Principal{
		UserID:         mustUUIDv7(t),
		OrganizationID: orgID,
		Email:          "org-admin@tenant.test",
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.ScopeOrgsRead,
	}
	eng := newAdminStateEngine(t, principal, counter)
	now := time.Now().UTC()
	if _, err := eng.orgRepo.Create(context.Background(), &domain.Organization{
		ID: orgID, Name: "tenant", Domain: "tenant.test", OrgSlug: "tenant",
		Active: true, MaxSessionsPerUser: 10, MFAPolicy: "optional",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	counter.admins[orgID] = 1
	counter.verified[orgID] = 1

	list := decodeOrgList(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations"))
	if len(list) != 1 {
		t.Fatalf("org_admin list returned %d rows, want 1", len(list))
	}
	requireAdminState(t, list[orgID], true, false)
}

// TestOrgAdminState_UnwiredCounterFatalAndAbsent pins clause 3: nil
// AdminCounter → fatal fault named organizations-admin-state AND the
// fields are ABSENT from list + get payloads (never false).
func TestOrgAdminState_UnwiredCounterFatalAndAbsent(t *testing.T) {
	eng := newAdminStateEngine(t, siteAdminPrincipal(), nil)

	if !eng.report.HasFatal() {
		t.Fatalf("unwired AdminCounter must record a FATAL fault")
	}
	named := false
	for _, f := range eng.report.Faults() {
		if f.Component == "organizations-admin-state" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name organizations-admin-state; got %+v", eng.report.Faults())
	}

	o := seedAdminStateOrg(t, eng, "unwired")
	list := decodeOrgList(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations"))
	requireAdminStateAbsent(t, list[o.ID])
	got := decodeOrg(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations/"+o.ID.String()))
	requireAdminStateAbsent(t, got)
	t.Logf("EVIDENCE unwired counter: fatal fault recorded; fields absent, never false; faults=%+v", eng.report.Faults())
}

// TestOrgAdminState_CounterErrorEmitsAbsent pins clause 4: a counter
// error at request time yields ABSENT fields on an otherwise-200
// response — the read surface stays up, and absence never collapses to
// a false "no admin".
func TestOrgAdminState_CounterErrorEmitsAbsent(t *testing.T) {
	counter := &fakeOrgAdminCounter{err: errors.New("db unavailable")}
	eng := newAdminStateEngine(t, siteAdminPrincipal(), counter)
	o := seedAdminStateOrg(t, eng, "counterr")

	list := decodeOrgList(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations"))
	requireAdminStateAbsent(t, list[o.ID])
	got := decodeOrg(t, adminStateDo(t, eng, http.MethodGet, "/api/v1/organizations/"+o.ID.String()))
	requireAdminStateAbsent(t, got)
}

// TestOrgAdminState_NoReportNoPanic: registering with an unwired counter
// and NO StartupReport must not panic (Fatal is nil-safe, P-018).
func TestOrgAdminState_NoReportNoPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("RegisterOrganizationsRoutes(nil AdminCounter, nil report) panicked: %v", rec)
		}
	}()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, newMemOrgRepo()),
	})
}

func mustUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuidv7: %v", err)
	}
	return id
}
