package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// v0.5.1: a first-run setup whose organization name yields no default domain
// (no letter or digit to slug) and whose domain was left empty is refused
// with its own 400, organization_domain_required — a wizard can say "enter a
// domain" instead of the generic setup_complete_failed.
func TestSetup_Complete_DomainRequiredIsItsOwn400(t *testing.T) {
	fake := &fakeSetupService{completeErr: fmt.Errorf("wrapped: %w", setup.ErrOrganizationDomainRequired)}
	e := newEngineWithFake(fake)

	body, _ := json.Marshal(map[string]string{
		"setup_token":         "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST",
		"organization_name":   "!!!",
		"organization_domain": "",
		"admin_email":         "owner@acme.example",
		"admin_password":      "Very-Long-Test-Password-1!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400; body=%q", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "organization_domain_required" {
		t.Fatalf("error = %v; want organization_domain_required", got["error"])
	}
}
