// target: internal/handlers/organization_create_conflict_test.go (OSS-0913-C item 3, red first)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type conflictOrgRepo struct {
	*memOrgRepo
	err error
}

func (r *conflictOrgRepo) Create(_ context.Context, _ *domain.Organization) (*domain.Organization, error) {
	return nil, r.err
}

func (r *conflictOrgRepo) CreateWithAdmin(_ context.Context, _ *domain.Organization, _ *domain.User) (*domain.Organization, *domain.User, error) {
	return nil, nil, r.err
}

// The create with an initial admin answers the same 409s, plus email_exists
// when admin_email already has an account; the store refused the pair, so
// nothing was created and no activation token is issued.
func TestCreateOrganization_WithAdmin_DuplicateAnswers409WithCode(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		wantCode int
		wantErr  string
	}{
		{"duplicate domain", domain.ErrOrganizationAlreadyExists, http.StatusConflict, "domain_exists"},
		{"duplicate slug", domain.ErrOrganizationSlugAlreadyExists, http.StatusConflict, "slug_exists"},
		{"admin email taken", domain.ErrUserAlreadyExists, http.StatusConflict, "email_exists"},
		{"other store error (control)", errors.New("boom"), http.StatusBadRequest, "invalid request"},
	} {
		repo := &conflictOrgRepo{memOrgRepo: newMemOrgRepo(), err: c.err}
		issuer := &countingActivationIssuer{}
		deps := OrganizationsHandlerDeps{Audit: audit.NoopService{}, OrganizationService: service.NewOrganizationService(nil, repo), ActivationIssuer: issuer}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(mw.InjectPrincipalForTest(siteAdminActor()))
		r.POST("/o", HandleCreateOrganization(deps))
		req := httptest.NewRequest(http.MethodPost, "/o", bytes.NewReader([]byte(`{"name":"Acme","domain":"acme.example","admin_email":"admin@acme.example"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != c.wantCode || body["error"] != c.wantErr {
			t.Errorf("%s: got %d %v, want %d error=%q", c.name, rec.Code, body["error"], c.wantCode, c.wantErr)
		}
		if c.wantCode == http.StatusConflict {
			if msg, _ := body["message"].(string); msg == "" {
				t.Errorf("%s: a 409 must carry a plain message", c.name)
			}
		}
		if issuer.calls != 0 {
			t.Errorf("%s: no activation token may be issued for a refused create, got %d", c.name, issuer.calls)
		}
	}
}

type countingActivationIssuer struct{ calls int }

func (i *countingActivationIssuer) IssueActivationToken(context.Context, *domain.User) (string, time.Time, error) {
	i.calls++
	return "unused", time.Time{}, nil
}

// A duplicate domain or slug on POST /api/v1/organizations answers 409 with
// a code the console can turn into plain words. At 3e1fa09 the handler
// answers 400 {"error":"invalid request"} for every Create error, so the
// console's existing 409 line ("An organization with this domain already
// exists.") never shows.
func TestCreateOrganization_DuplicateAnswers409WithCode(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		wantCode int
		wantErr  string
	}{
		{"duplicate domain", domain.ErrOrganizationAlreadyExists, http.StatusConflict, "domain_exists"},
		{"duplicate slug", domain.ErrOrganizationSlugAlreadyExists, http.StatusConflict, "slug_exists"},
		{"other store error (control)", errors.New("boom"), http.StatusBadRequest, "invalid request"},
	} {
		repo := &conflictOrgRepo{memOrgRepo: newMemOrgRepo(), err: c.err}
		deps := OrganizationsHandlerDeps{Audit: audit.NoopService{}, OrganizationService: service.NewOrganizationService(nil, repo)}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(mw.InjectPrincipalForTest(siteAdminActor()))
		r.POST("/o", HandleCreateOrganization(deps))
		req := httptest.NewRequest(http.MethodPost, "/o", bytes.NewReader([]byte(`{"name":"Acme","domain":"acme.example"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != c.wantCode || body["error"] != c.wantErr {
			t.Errorf("%s: got %d %v, want %d error=%q", c.name, rec.Code, body["error"], c.wantCode, c.wantErr)
		}
		if c.wantCode == http.StatusConflict {
			if msg, _ := body["message"].(string); msg == "" {
				t.Errorf("%s: a 409 must carry a plain message", c.name)
			}
		}
	}
}
