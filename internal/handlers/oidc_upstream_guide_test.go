package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// FUNC-H4 (audits/oss-functionality-2026-10-05.md): docs/guides/oidc-upstream-login.md
// must work as written. Its request body is taken from the guide itself and
// sent to the route the guide names, so the guide and the API cannot drift
// apart again: the old guide's flat field table answered 400.

func guideRequestBody(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/guides/oidc-upstream-login.md")
	if err != nil {
		t.Fatalf("read the guide: %v", err)
	}
	doc := string(raw)
	start := strings.Index(doc, "```json\n")
	if start < 0 {
		t.Fatal("the guide shows no JSON request body for POST /api/v1/organizations/{org_id}/identity-provider")
	}
	body := doc[start+len("```json\n"):]
	end := strings.Index(body, "```")
	if end < 0 {
		t.Fatal("the guide's JSON block is not closed")
	}
	return body[:end]
}

func TestUpstreamOIDCGuide_TheBodyAsWrittenCreatesTheProvider(t *testing.T) {
	org := uuid.New()
	r, repo, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
	req := httptest.NewRequest(http.MethodPost, idpPath(org), bytes.NewBufferString(guideRequestBody(t)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("the guide's body = %d %s; want 201", w.Code, w.Body.String())
	}
	if len(repo.byID) != 1 {
		t.Fatalf("providers stored = %d; want 1", len(repo.byID))
	}
	for _, p := range repo.byID {
		if p.Config.IssuerURL == "" || p.Config.ClientID == "" || len(p.Config.EmailDomains) == 0 {
			t.Errorf("the guide's body did not set issuer, client and domains: %+v", p.Config)
		}
	}
}
