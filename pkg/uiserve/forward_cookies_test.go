package uiserve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// A cookie-session API (identuum-idp-ce) authenticates /api/v1 by its own
// session cookie, not a Bearer: the boundary passes ONLY the cookies named
// in ForwardCookies, unchanged, lifts nothing, and still drops every other
// cookie the browser sent.
func TestForwardCookies_PassOnlyTheNamedCookiesAndLiftNothing(t *testing.T) {
	var gotCookies []string
	var gotAuth string
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			gotCookies = append(gotCookies, c.Name+"="+c.Value)
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	h, err := New(Options{
		UI:             fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}},
		API:            api,
		ForwardCookies: []string{"edition_session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/bff/api/v1/probe", nil)
	req.Header.Set(RequestHeader, RequestHeaderValue)
	req.Header.Set("Cookie", "edition_session=s1; access_token=t1; tracker=x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if strings.Join(gotCookies, ";") != "edition_session=s1" {
		t.Fatalf("cookies reaching the API = %v, want only edition_session=s1", gotCookies)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want none (no AccessCookie configured)", gotAuth)
	}
}
