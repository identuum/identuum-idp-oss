package api

import (
	"net/http/httptest"
	"testing"
)

func TestUI_BFF_RefreshRequiresBrowserProofAndLiveServices(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, tc := range []struct {
		name, method, origin, authorization string
		proof                               bool
		want                                int
	}{
		{"unwired", "POST", "", "", true, 503},
		{"missing_csrf", "POST", "", "", false, 403},
		{"foreign_origin", "POST", "https://other.test", "", true, 403},
		{"explicit_bearer", "POST", "", "Bearer other", true, 400},
		{"get", "GET", "", "", true, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/bff/session/refresh", nil)
			if tc.proof {
				req.Header.Set(uiBFFRequiredHeader, uiBFFRequiredHeaderValue)
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("refused refresh must not change cookies")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("refresh must prohibit storage")
			}
		})
	}
}
