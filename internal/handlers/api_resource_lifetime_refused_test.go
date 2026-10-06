package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-MUST1-RETIRE-TTL (owner rulings l-n, 2026-10-06): OSS has one
// access-token lifetime, 1 hour, and no per-resource lifetime. Create and
// update of an API resource REFUSE a request that contains token_ttl_secs
// with 400 naming the field and echoing no request body; the same request
// without it is served as before; no response carries the field.

type lifetimeAPIResourceRepo struct {
	statusAPIResourceRepo
	createCalls int
}

func (r *lifetimeAPIResourceRepo) Create(_ context.Context, res *domain.APIResource, _ []domain.APIScope) error {
	r.createCalls++
	r.stored = *res
	return nil
}

func lifetimeRecorder(t *testing.T, p *domain.Principal, method, route, path, body string, h gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	r.Handle(method, route, h)
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAPIResourceLifetime_RefusedOnCreateAndUpdate(t *testing.T) {
	orgID, resID := uuid.New(), uuid.New()
	actor := &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	newDeps := func() (*lifetimeAPIResourceRepo, APIResourcesHandlerDeps) {
		repo := &lifetimeAPIResourceRepo{statusAPIResourceRepo: statusAPIResourceRepo{stored: domain.APIResource{
			ID: resID, OrganizationID: orgID, Name: "Billing API", Audience: "https://billing.example.test",
			TokenTTLSecs: 600, Active: true,
		}}}
		return repo, APIResourcesHandlerDeps{Audit: audit.NoopService{}, APIResourceService: service.NewAPIResourceService(nil, repo)}
	}
	const marker = "echo-marker-7f3a"
	wantRefusal := func(t *testing.T, label string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", label, rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v", label, err)
		}
		if body["field"] != "token_ttl_secs" || body["error"] != "unsupported_field" {
			t.Errorf("%s: body %v must name the field token_ttl_secs with error unsupported_field", label, body)
		}
		if strings.Contains(rec.Body.String(), marker) || strings.Contains(rec.Body.String(), "600") {
			t.Errorf("%s: the refusal echoed the request body: %s", label, rec.Body.String())
		}
	}

	// create with the field: refused, nothing written
	repo, deps := newDeps()
	rec := lifetimeRecorder(t, actor, http.MethodPost, "/r", "/r",
		`{"name":"`+marker+`","audience":"https://new.example.test","token_ttl_secs":600}`, HandleCreateAPIResource(deps))
	wantRefusal(t, "create with token_ttl_secs", rec)
	if repo.createCalls != 0 {
		t.Errorf("a refused create reached the repository %d time(s)", repo.createCalls)
	}
	// even a null value is refused: the field itself is not accepted
	_, deps = newDeps()
	wantRefusal(t, "create with token_ttl_secs null", lifetimeRecorder(t, actor, http.MethodPost, "/r", "/r",
		`{"name":"x-`+marker+`","audience":"https://new.example.test","token_ttl_secs":null}`, HandleCreateAPIResource(deps)))

	// update with the field: refused, nothing written
	repo, deps = newDeps()
	rec = lifetimeRecorder(t, actor, http.MethodPut, "/r/:id", "/r/"+resID.String(),
		`{"name":"`+marker+`","token_ttl_secs":600}`, HandleUpdateAPIResource(deps))
	wantRefusal(t, "update with token_ttl_secs", rec)
	if repo.updateCalls != 0 {
		t.Errorf("a refused update reached the repository %d time(s)", repo.updateCalls)
	}

	// the same requests without the field: served as before, and no response
	// carries a lifetime
	repo, deps = newDeps()
	rec = lifetimeRecorder(t, actor, http.MethodPost, "/r", "/r",
		`{"name":"Fresh API","audience":"https://fresh.example.test"}`, HandleCreateAPIResource(deps))
	if rec.Code != http.StatusCreated || repo.createCalls != 1 {
		t.Fatalf("create without the field: status %d, creates %d; want 201 and 1", rec.Code, repo.createCalls)
	}
	if strings.Contains(rec.Body.String(), "token_ttl_secs") {
		t.Errorf("the create response carries token_ttl_secs: %s", rec.Body.String())
	}
	repo, deps = newDeps()
	rec = lifetimeRecorder(t, actor, http.MethodPut, "/r/:id", "/r/"+resID.String(),
		`{"name":"Billing API v2"}`, HandleUpdateAPIResource(deps))
	if rec.Code != http.StatusOK || repo.updateCalls != 1 {
		t.Fatalf("update without the field: status %d, updates %d; want 200 and 1", rec.Code, repo.updateCalls)
	}
	if strings.Contains(rec.Body.String(), "token_ttl_secs") {
		t.Errorf("the update response carries token_ttl_secs: %s", rec.Body.String())
	}
	// the legacy stored value is kept, never shown (ruling n)
	if repo.stored.TokenTTLSecs != 600 {
		t.Errorf("an update without the field changed the stored legacy value to %d", repo.stored.TokenTTLSecs)
	}
	_, deps = newDeps()
	rec = lifetimeRecorder(t, actor, http.MethodGet, "/r/:id", "/r/"+resID.String(), "", HandleGetAPIResource(deps))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "token_ttl_secs") {
		t.Errorf("get: status %d, body names token_ttl_secs: %v", rec.Code, strings.Contains(rec.Body.String(), "token_ttl_secs"))
	}
}
