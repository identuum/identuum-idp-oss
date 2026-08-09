package handlers

// Per-org DCR gating tests. SCIM v2 (a paid CE feature — Professional and above) was removed from
// the OSS tree to close a licensing leak — see
// docs/audit/changelog/scim-oss-leak-removal.md. The SCIM halves of the
// former dcr_scim_org_config_test.go (the per-org SCIM gate, SCIM discovery,
// and the SCIM target-org tests) were excised; the DCR coverage below — which
// exercises the SAME shared per-org protocol-settings gate via
// OrgFeatureLookup — is retained intact.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// stubOrgFeatureLookup is the per-org gate stub. Returns the
// stored value for (orgID, feature) when present; otherwise
// returns false. Used to wire deterministic org-level toggles
// into the handler-side gate under test.
type stubOrgFeatureLookup struct {
	mu   sync.Mutex
	bits map[uuid.UUID]map[string]bool
	// errFor, when non-nil for an orgID, returns an error from
	// IsFeatureEnabledForOrg so the 503 path can be exercised.
	errFor map[uuid.UUID]error
}

func newStubOrgFeatureLookup() *stubOrgFeatureLookup {
	return &stubOrgFeatureLookup{
		bits:   map[uuid.UUID]map[string]bool{},
		errFor: map[uuid.UUID]error{},
	}
}

func (s *stubOrgFeatureLookup) set(orgID uuid.UUID, feature string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bits[orgID] == nil {
		s.bits[orgID] = map[string]bool{}
	}
	s.bits[orgID][feature] = enabled
}

func (s *stubOrgFeatureLookup) IsFeatureEnabledForOrg(_ context.Context, orgID uuid.UUID, feature string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.errFor[orgID]; err != nil {
		return false, err
	}
	if m, ok := s.bits[orgID]; ok {
		return m[feature], nil
	}
	return false, nil
}

// orgConfigEngine wires DCR + IAT mgmt + RFC 7592 mgmt with a
// caller-supplied OrgFeatureLookup so the per-org gate can be
// exercised end-to-end.
type orgConfigEngine struct {
	r          *gin.Engine
	clientRepo *memClientRepo
	iatRepo    *memIATRepo
	ratRepo    *memRATRepo
	rec        *audit.Recorder
	iatSvc     *service.DCRInitialAccessTokenService
	ratSvc     *service.DCRRegistrationAccessTokenService
	lookup     *stubOrgFeatureLookup
}

func newOrgConfigEngine(t *testing.T, lookup *stubOrgFeatureLookup, principal *domain.Principal) orgConfigEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	clientRepo := newMemClientRepo()
	iatRepo := newMemIATRepo()
	ratRepo := newMemRATRepo()
	rec := &audit.Recorder{}

	clientSvc := service.NewClientService(nil, clientRepo)
	iatSvc := service.NewDCRInitialAccessTokenService(nil, iatRepo)
	ratSvc := service.NewDCRRegistrationAccessTokenService(nil, ratRepo)

	// The OrgFeatureLookup adapter must be nil when the caller
	// passes a nil stub — that preserves the open default and
	// proves the regression contract.
	var olookup OrgFeatureLookup
	if lookup != nil {
		olookup = lookup
	}
	RegisterDCRRoutes(r, DCRHandlerDeps{
		ClientService:       clientSvc,
		IATService:          iatSvc,
		RATService:          ratSvc,
		RegistrationBaseURL: "https://idp.example.com",
		Audit:               rec,
		OrgFeatureLookup:    olookup,
	})
	RegisterDCRInitialAccessTokenRoutes(r, DCRInitialAccessTokenHandlerDeps{
		IATService: iatSvc,
		Audit:      rec,
	})
	RegisterDCRManagementRoutes(r, DCRManagementHandlerDeps{
		ClientService:    clientSvc,
		RATService:       ratSvc,
		Audit:            rec,
		OrgFeatureLookup: olookup,
	})
	return orgConfigEngine{
		r: r, clientRepo: clientRepo, iatRepo: iatRepo, ratRepo: ratRepo,
		rec: rec, iatSvc: iatSvc, ratSvc: ratSvc, lookup: lookup,
	}
}

func orgConfigJSON(t *testing.T, eng orgConfigEngine, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// TestOrgConfig_DCREnabled_SiteAdminRegisterWorks pins the
// happy path: when the target org has DCR enabled, a site_admin
// DCR /register that resolves to that org (via IAT or via
// org-less request) succeeds.
func TestOrgConfig_DCREnabled_SiteAdminRegisterWorks(t *testing.T) {
	org := uuid.New()
	lookup := newStubOrgFeatureLookup()
	lookup.set(org, service.OrgFeatureDynamicClientRegistration, true)
	eng := newOrgConfigEngine(t, lookup, siteAdminPrincipal())
	// Mint an org-bound IAT then consume with no principal.
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL:            time.Hour,
		MaxUses:        1,
		OrganizationID: &org,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "OK",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
}

// TestOrgConfig_DCRDisabled_SiteAdminRegisterBlocked pins the
// gate path: when the target org has DCR disabled, a site_admin
// DCR /register targeting that org (via IAT) returns 403.
func TestOrgConfig_DCRDisabled_SiteAdminRegisterBlocked(t *testing.T) {
	org := uuid.New()
	lookup := newStubOrgFeatureLookup() // default: both false for every org
	eng := newOrgConfigEngine(t, lookup, siteAdminPrincipal())
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL:            time.Hour,
		MaxUses:        1,
		OrganizationID: &org,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Blocked",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "feature not enabled" {
		t.Errorf("error = %v, want 'feature not enabled'", env["error"])
	}
	if env["feature"] != service.OrgFeatureDynamicClientRegistration {
		t.Errorf("feature = %v, want %q", env["feature"], service.OrgFeatureDynamicClientRegistration)
	}
}

// TestOrgConfig_DCRDisabled_OrgLessSiteAdminStillWorks pins
// the documented convention: a site_admin DCR call WITHOUT an
// org binding (org-less, infra-level client) is NOT gated.
func TestOrgConfig_DCRDisabled_OrgLessSiteAdminStillWorks(t *testing.T) {
	lookup := newStubOrgFeatureLookup() // empty: every org disabled
	eng := newOrgConfigEngine(t, lookup, siteAdminPrincipal())
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Infra",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("org-less site_admin DCR blocked: status = %d", rec.Code)
	}
}

// TestOrgConfig_DCRDisabled_ValidIATCannotBypass pins that an
// IAT bound to a DCR-disabled org cannot register a client.
func TestOrgConfig_DCRDisabled_ValidIATCannotBypass(t *testing.T) {
	org := uuid.New()
	lookup := newStubOrgFeatureLookup() // disabled for `org`
	eng := newOrgConfigEngine(t, lookup, nil)
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL:            time.Hour,
		MaxUses:        1,
		OrganizationID: &org,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Bypass Attempt",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("valid IAT bypassed disabled org gate: status = %d", rec.Code)
	}
}

// TestOrgConfig_DCRDisabled_ValidRATCannotBypass pins that a
// valid RAT against a client whose org has DCR disabled cannot
// reach the RFC 7592 management surface.
func TestOrgConfig_DCRDisabled_ValidRATCannotBypass(t *testing.T) {
	enabledOrg := uuid.New()
	lookup := newStubOrgFeatureLookup()
	lookup.set(enabledOrg, service.OrgFeatureDynamicClientRegistration, true)
	eng := newOrgConfigEngine(t, lookup, siteAdminPrincipal())
	// Register a client in enabledOrg, mint a RAT, then flip
	// the org's DCR to false and confirm the RAT can no longer
	// be used.
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL: time.Hour, MaxUses: 1, OrganizationID: &enabledOrg,
	})
	if err != nil {
		t.Fatalf("Issue IAT: %v", err)
	}
	regRec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "RAT Test",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d", regRec.Code)
	}
	var regResp dcrResponse
	_ = json.Unmarshal(regRec.Body.Bytes(), &regResp)
	if regResp.RegistrationAccessToken == "" {
		t.Fatalf("no RAT minted")
	}
	// Recover the client UUID.
	var clientUUID uuid.UUID
	for id := range eng.clientRepo.rows {
		clientUUID = id
		break
	}
	// Flip the org to disabled.
	lookup.set(enabledOrg, service.OrgFeatureDynamicClientRegistration, false)
	rec := orgConfigJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+clientUUID.String(), nil, regResp.RegistrationAccessToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("RAT bypassed flipped-disabled org: status = %d, want 403", rec.Code)
	}
}

// TestOrgConfig_DCRNilLookupAllowsEverything pins the regression
// contract: a handler dep with no OrgFeatureLookup wired
// (existing test fixtures and smoke binaries) behaves exactly as
// before — DCR /register reachable.
func TestOrgConfig_DCRNilLookupAllowsEverything(t *testing.T) {
	eng := newOrgConfigEngine(t, nil, siteAdminPrincipal())
	if rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Nil Open",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, ""); rec.Code != http.StatusCreated {
		t.Errorf("DCR /register with nil lookup: status = %d, want 201", rec.Code)
	}
}

// TestOrgConfig_IATMgmtNotPerOrgGated pins the documented
// choice: the IAT issue/list/revoke admin surface is NOT
// per-org gated, so an operator can still mint an IAT for an
// org that wants to turn DCR on.
func TestOrgConfig_IATMgmtNotPerOrgGated(t *testing.T) {
	lookup := newStubOrgFeatureLookup() // every org disabled
	eng := newOrgConfigEngine(t, lookup, siteAdminPrincipal())
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{
		"ttl_seconds": 60,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Errorf("IAT issue: status = %d, want 201 (IAT mgmt is admin housekeeping, not per-org gated)", rec.Code)
	}
}
