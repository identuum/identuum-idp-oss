package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bffProof is the request header every /bff request must carry since D1.
var bffProof = withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue)

func uiDo(e http.Handler, method, target string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// Owner decision D1 (PLAN-C-CLOSE, 2026-09-23), unit proofs: EVERY /bff
// request — safe methods included — carries the X-Requested-With proof and a
// permitted origin, so a cross-site top-level GET (a link, a redirect, an
// <img>) can never make the boundary lift the victim's Lax access cookie.
// The refusal happens before any credential is lifted or dispatched.

func TestUIBFF_D1_SafeMethodWithoutProofNeverLiftsTheCookie(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := uiDo(e, method, "/bff/api/v1/probe", withCookie("good"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s /bff without the request header: %d %q, want 403 csrf_failed", method, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "alice@example.test") {
			t.Fatalf("%s /bff without the request header lifted the cookie: %q", method, rec.Body.String())
		}
	}
}

func TestUIBFF_D1_CrossSiteFetchMetadataIsRefusedEvenWithTheHeader(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, site := range []string{"cross-site", "same-site"} {
		rec := uiGet(e, "/bff/api/v1/probe", withCookie("good"),
			withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue),
			withHeader("Sec-Fetch-Site", site))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "alice@example.test") {
			t.Fatalf("GET with Sec-Fetch-Site %s: %d %q, want 403 and no lift", site, rec.Code, rec.Body.String())
		}
	}
	// A foreign Origin on a GET is refused as on a POST.
	rec := uiGet(e, "/bff/api/v1/probe", withCookie("good"),
		withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue),
		withHeader("Origin", "https://evil.example"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET with a foreign Origin: %d %q, want 403", rec.Code, rec.Body.String())
	}
}

func TestUIBFF_D1_SameOriginGetWithTheHeaderStillLifts(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, site := range []string{"same-origin", ""} {
		mut := []func(*http.Request){withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue)}
		if site != "" {
			mut = append(mut, withHeader("Sec-Fetch-Site", site))
		}
		rec := uiGet(e, "/bff/api/v1/probe", mut...)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"alice@example.test"`) {
			t.Fatalf("same-origin GET (Sec-Fetch-Site %q): %d %q, want 200 and the lifted principal", site, rec.Code, rec.Body.String())
		}
	}
}
