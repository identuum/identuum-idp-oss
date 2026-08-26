// organization_create_test.go — BORN-ACTIVE-1 + ORG-CREATE-ADMIN-1.
//
// THE-BORN-DEACTIVATED (2026-08-26), found by clicking: the create
// handler bound `Active bool` — so the UI, which never sends `active`,
// birthed every organization DEACTIVATED — and had no admin_email field
// at all, silently dropping the initial-admin half of the UI's create
// contract. These tests pin the repaired contract at the HTTP boundary:
//
//	BORN-ACTIVE-1     absent `active` means ACTIVE; an explicit value
//	                  is honored.
//	ORG-CREATE-ADMIN-1 admin_email mints the org + initial org_admin
//	                  ATOMICALLY (repo.CreateWithAdmin), born INACTIVE
//	                  for the activation ceremony, activation_token in
//	                  the response; active:true alongside admin_email
//	                  is a loud 400; an unwired issuer is a loud 503.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// createCaptureRepo records what the service handed the repository.
// Unused interface methods come from the embedded nil interface and
// panic if reached — this test path never reaches them.
type createCaptureRepo struct {
	repository.OrganizationRepository
	created             *domain.Organization
	withAdminOrg        *domain.Organization
	withAdminUser       *domain.User
	failCreateWithAdmin bool
}

func (r *createCaptureRepo) Create(_ context.Context, org *domain.Organization) (*domain.Organization, error) {
	r.created = org
	return org, nil
}

func (r *createCaptureRepo) CreateWithAdmin(_ context.Context, org *domain.Organization, adminUser *domain.User) (*domain.Organization, *domain.User, error) {
	if r.failCreateWithAdmin {
		return nil, nil, context.DeadlineExceeded
	}
	r.withAdminOrg = org
	r.withAdminUser = adminUser
	return org, adminUser, nil
}

type stubActivationIssuer struct{ raw string }

func (s stubActivationIssuer) IssueActivationToken(context.Context, *domain.User) (string, time.Time, error) {
	return s.raw, time.Now().Add(time.Hour), nil
}

func newCreateOrgEngine(t *testing.T, deps OrganizationsHandlerDeps) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{
		UserID: uuid.New(),
		Email:  "site_admin@system.local",
		Role:   domain.RoleSiteAdmin,
	}))
	RegisterOrganizationsRoutes(r, deps)
	return r
}

func postCreateOrg(t *testing.T, r *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// RULE: BORN-ACTIVE-1
func TestCreateOrganization_AbsentActiveMeansActive(t *testing.T) {
	repo := &createCaptureRepo{}
	deps := OrganizationsHandlerDeps{OrganizationService: service.NewOrganizationService(nil, repo)}
	r := newCreateOrgEngine(t, deps)

	w := postCreateOrg(t, r, `{"name":"Acme","domain":"acme.example"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if repo.created == nil || !repo.created.Active {
		t.Fatal("an org created WITHOUT an `active` field must be born ACTIVE — the UI never sends it")
	}
}

func TestCreateOrganization_ExplicitActiveIsHonoredBothWays(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"name":"Acme","domain":"acme.example","active":false}`, false},
		{`{"name":"Acme","domain":"acme.example","active":true}`, true},
	} {
		repo := &createCaptureRepo{}
		deps := OrganizationsHandlerDeps{OrganizationService: service.NewOrganizationService(nil, repo)}
		w := postCreateOrg(t, newCreateOrgEngine(t, deps), tc.body)
		if w.Code != http.StatusCreated {
			t.Fatalf("want 201, got %d", w.Code)
		}
		if repo.created.Active != tc.want {
			t.Fatalf("explicit active must be honored: body %s, stored active=%v", tc.body, repo.created.Active)
		}
	}
}

// RULE: ORG-CREATE-ADMIN-1
func TestCreateOrganization_AdminEmailMintsAtomicInactivePair(t *testing.T) {
	repo := &createCaptureRepo{}
	deps := OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, repo),
		ActivationIssuer:    stubActivationIssuer{raw: "tok-raw-1"},
	}
	w := postCreateOrg(t, newCreateOrgEngine(t, deps),
		`{"name":"Acme","domain":"acme.example","admin_email":"  Admin@Acme.Example "}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if repo.created != nil {
		t.Fatal("admin_email must use the ATOMIC CreateWithAdmin path, not plain Create")
	}
	if repo.withAdminOrg == nil || repo.withAdminUser == nil {
		t.Fatal("CreateWithAdmin must receive the org + admin pair")
	}
	if repo.withAdminOrg.Active {
		t.Fatal("an org created WITH admin_email must be born INACTIVE — the activation ceremony flips it")
	}
	if repo.withAdminUser.Role != domain.RoleOrgAdmin {
		t.Fatalf("initial admin role = %s, want org_admin", repo.withAdminUser.Role)
	}
	if repo.withAdminUser.Email != "admin@acme.example" {
		t.Fatalf("admin email must be normalized, got %q", repo.withAdminUser.Email)
	}
	if repo.withAdminUser.PasswordHash == "" {
		t.Fatal("the pending admin must carry a placeholder hash (password-required invariant)")
	}
	var resp struct {
		Organization    map[string]any `json:"organization"`
		ActivationToken string         `json:"activation_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.ActivationToken != "tok-raw-1" || resp.Organization == nil {
		t.Fatalf("the response must carry the organization and the activation token, got %s", w.Body.String())
	}
}

func TestCreateOrganization_AdminEmailRefusals(t *testing.T) {
	repo := &createCaptureRepo{}
	svc := service.NewOrganizationService(nil, repo)

	// active:true alongside admin_email contradicts the activation
	// ceremony (it refuses already-active orgs) — loud 400.
	deps := OrganizationsHandlerDeps{OrganizationService: svc, ActivationIssuer: stubActivationIssuer{raw: "t"}}
	w := postCreateOrg(t, newCreateOrgEngine(t, deps),
		`{"name":"Acme","domain":"acme.example","admin_email":"a@b.example","active":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "active_conflicts_with_admin_email") {
		t.Fatalf("active:true + admin_email must 400 by name, got %d (%s)", w.Code, w.Body.String())
	}

	// An unwired issuer must refuse loudly — never silently drop the
	// admin half (the original defect's failure mode).
	deps = OrganizationsHandlerDeps{OrganizationService: svc}
	w = postCreateOrg(t, newCreateOrgEngine(t, deps),
		`{"name":"Acme","domain":"acme.example","admin_email":"a@b.example"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin_email against an unwired issuer must 503, got %d", w.Code)
	}

	// Atomicity: a failing CreateWithAdmin creates NOTHING and reports 400.
	repo.failCreateWithAdmin = true
	deps = OrganizationsHandlerDeps{OrganizationService: svc, ActivationIssuer: stubActivationIssuer{raw: "t"}}
	w = postCreateOrg(t, newCreateOrgEngine(t, deps),
		`{"name":"Acme","domain":"acme.example","admin_email":"a@b.example"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a failed atomic create must 400, got %d", w.Code)
	}
	if repo.withAdminOrg != nil || repo.created != nil {
		t.Fatal("a failed atomic create must record nothing")
	}
}
