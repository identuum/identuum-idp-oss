package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRespondDCRError_PinsCurrentContract pins the current
// response-shape contract of the DCR error helper. The helper is
// high-use (~55 call sites across internal/handlers/dcr.go
// HandleDCRRegister branches per gograph_callers on 2026-06-24) but
// had no direct unit tests prior to slice agent-a-20260721. The
// contract pinned here matches RFC 7591 §3.2.2:
// {"error":"<code>","error_description":"<desc>"}.
func TestRespondDCRError_PinsCurrentContract(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	cases := []struct {
		name   string
		status int
		code   string
		desc   string
	}{
		{"invalid_client_metadata", http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required"},
		{"unauthorized", http.StatusUnauthorized, "invalid_token", "Initial Access Token required"},
		{"forbidden", http.StatusForbidden, "insufficient_scope", "missing dcr scope"},
		{"server_error", http.StatusInternalServerError, "server_error", "internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST("/x", func(c *gin.Context) { respondDCRError(c, tc.status, tc.code, tc.desc) })
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Fatalf("http status=%d want=%d", rec.Code, tc.status)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Fatalf("Content-Type=%q want application/json prefix (gin.JSON default)", got)
			}
			// Helper does NOT set Cache-Control / Pragma today. If a future
			// change adds RFC-6749-style no-store headers, this fires for review.
			if cc := rec.Header().Get("Cache-Control"); cc != "" {
				t.Fatalf("Cache-Control=%q expected empty (helper does not set cache headers today)", cc)
			}
			if pr := rec.Header().Get("Pragma"); pr != "" {
				t.Fatalf("Pragma=%q expected empty (helper does not set cache headers today)", pr)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v (raw=%q)", err, rec.Body.String())
			}
			if got, _ := body["error"].(string); got != tc.code {
				t.Fatalf("error=%q want=%q", got, tc.code)
			}
			if got, _ := body["error_description"].(string); got != tc.desc {
				t.Fatalf("error_description=%q want=%q (helper echoes caller-provided description verbatim — caller responsible for not leaking secrets)", got, tc.desc)
			}
			for k := range body {
				if k != "error" && k != "error_description" {
					t.Fatalf("unexpected field %q in DCR error envelope (helper currently emits exactly error+error_description)", k)
				}
			}
		})
	}
}
