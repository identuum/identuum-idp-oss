package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// THE-BROWSER-BOUNDARY-IN-GO-2 (Plan C), unit proofs against the whole engine.

// The static fallback must never answer for the API or operational surface.
// A fixed prefix list only covers the prefixes someone remembered: a route
// registered under any other first segment (a POST-only OAuth-style path,
// say) answered a GET — and an unknown sibling path — with the app shell,
// 200 text/html, where the engine alone answers 404. The reservation now
// includes the first segment of every route the engine actually carries.
func TestUISeam_RegisteredRouteSegmentsNeverBecomeTheShell(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	e.POST("/oauth2/token", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	// A wrong method on the registered route is the engine's 405 (OSS-405).
	if rec := uiGet(e, "/oauth2/token"); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" ||
		strings.Contains(rec.Body.String(), "<title>shell</title>") {
		t.Fatalf("GET /oauth2/token: %d Allow=%q %q, want 405 Allow: POST, never the shell", rec.Code, rec.Header().Get("Allow"), rec.Body.String())
	}
	for _, p := range []string{"/oauth2/unknown", "/oauth2"} {
		rec := uiGet(e, p)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<title>shell</title>") {
			t.Fatalf("GET %s: %d %q, want the engine's plain 404, never the shell", p, rec.Code, rec.Body.String())
		}
	}
	// The shell still answers its own client-side routes.
	if rec := uiGet(e, "/org-admin/users/123"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>shell</title>") {
		t.Fatalf("client route: %d %q, want the shell", rec.Code, rec.Body.String())
	}
}

// The boundary forwards only to a canonical /api/v1/ path. A target that is
// not its own cleaned form (dot segments, doubled or trailing slashes) or
// that carries an escape is refused BY THE BOUNDARY, before any credential
// is lifted or anything is dispatched into the engine.
func TestUISeam_BFFForwardsOnlyCanonicalAPIPaths(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, target := range []string{
		"/bff/api/v1/probe/../probe",
		"/bff/api/v1/x/../../setup/status",
		"/bff/api/v1//probe",
		"/bff/api/v1/probe/",
		"/bff/api/v1/./probe",
		"/bff/api/v1/probe%2F..%2Fguarded",
	} {
		rec := uiGet(e, target, withCookie("good"))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "bff_destination_refused") {
			t.Fatalf("GET %s: %d %q, want the boundary's own 404 bff_destination_refused", target, rec.Code, rec.Body.String())
		}
	}
	// The canonical path still works.
	if rec := uiGet(e, "/bff/api/v1/probe", withCookie("good"), bffProof); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"alice@example.test"`) {
		t.Fatalf("canonical path: %d %q", rec.Code, rec.Body.String())
	}
}
