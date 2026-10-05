package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// FUNC-M6 (audits/oss-functionality-2026-10-05.md): the wizard's hint said
// "At least 12 characters"; `abcdefghijkl` answered 400 setup_complete_failed
// and the wizard could only say "setup complete failed". A password refusal
// now names the rule it broke.
func TestSetup_Complete_PasswordRefusalSaysWhy(t *testing.T) {
	policyErr := domain.ValidatePassword("abcdefghijkl", 12)
	fake := &fakeSetupService{completeErr: fmt.Errorf("setup complete: admin_password failed strict policy: %w", policyErr)}
	e := newEngineWithFake(fake)

	body, _ := json.Marshal(map[string]string{
		"setup_token":       "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST",
		"organization_name": "Acme",
		"admin_email":       "owner@acme.example",
		"admin_password":    "abcdefghijkl",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "weak_password" {
		t.Fatalf("error = %v; want weak_password", got["error"])
	}
	msg, _ := got["message"].(string)
	if !strings.Contains(msg, "uppercase") || strings.Contains(msg, "abcdefghijkl") {
		t.Fatalf("message = %q; want the broken rule, never the password", msg)
	}
}
