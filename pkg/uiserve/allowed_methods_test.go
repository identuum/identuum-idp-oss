package uiserve

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// OSS-405: with Options.AllowedMethods, a /bff request whose method the API
// does not serve at the target is answered 405 with Allow before the browser
// proof and never forwarded; without it, every answer is what it was.

func allowedMethodsHandler(t *testing.T, hook func(method, path string) []string, forwarded *int) http.Handler {
	t.Helper()
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*forwarded++
		w.WriteHeader(http.StatusNoContent)
	})
	h, err := New(Options{
		UI:             fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}},
		API:            api,
		AllowedMethods: hook,
		Refresh:        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
		Logout:         LogoutOptions{Target: "/api/v1/auth/logout"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// postOnly serves POST at /api/v1/auth/login only.
func postOnly(method, path string) []string {
	if path == "/api/v1/auth/login" && method != http.MethodPost {
		return []string{http.MethodPost}
	}
	return nil
}

func serveBFF(h http.Handler, method, target string, proof bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if proof {
		req.Header.Set(RequestHeader, RequestHeaderValue)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowedMethods_AWrongMethodIsAnswered405AndNeverForwarded(t *testing.T) {
	forwarded := 0
	h := allowedMethodsHandler(t, postOnly, &forwarded)
	for _, proof := range []bool{false, true} {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := serveBFF(h, m, "/bff/api/v1/auth/login", proof)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" ||
				rec.Body.String() != `{"error":"method_not_allowed"}` {
				t.Errorf("%s (proof %v): %d Allow=%q %s; want 405 Allow: POST", m, proof, rec.Code, rec.Header().Get("Allow"), rec.Body)
			}
		}
	}
	if forwarded != 0 {
		t.Fatalf("forwarded %d wrong-method requests, want 0", forwarded)
	}
	// The right method without the proof is still refused, and with it forwarded.
	if rec := serveBFF(h, http.MethodPost, "/bff/api/v1/auth/login", false); rec.Code != http.StatusForbidden {
		t.Fatalf("POST without the proof: %d, want 403", rec.Code)
	}
	if rec := serveBFF(h, http.MethodPost, "/bff/api/v1/auth/login", true); rec.Code != http.StatusNoContent || forwarded != 1 {
		t.Fatalf("POST with the proof: %d, forwarded %d; want 204, 1", rec.Code, forwarded)
	}
	// A path the hook does not know is forwarded as before.
	if rec := serveBFF(h, http.MethodGet, "/bff/api/v1/other", true); rec.Code != http.StatusNoContent || forwarded != 2 {
		t.Fatalf("GET an unknown target: %d, forwarded %d; want 204, 2", rec.Code, forwarded)
	}
}

func TestAllowedMethods_TheSessionRoutesAnswerAWrongMethod405(t *testing.T) {
	forwarded := 0
	h := allowedMethodsHandler(t, postOnly, &forwarded)
	for _, p := range []string{RefreshPath, LogoutPath} {
		rec := serveBFF(h, http.MethodGet, p, false)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Errorf("GET %s: %d Allow=%q; want 405 Allow: POST", p, rec.Code, rec.Header().Get("Allow"))
		}
		if rec := serveBFF(h, http.MethodPost, p, false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without the proof: %d; want 403", p, rec.Code)
		}
	}
	if forwarded != 0 {
		t.Fatalf("forwarded %d, want 0", forwarded)
	}
}

// Without the hook nothing moves: the wrong method is forwarded after the
// proof, and the session routes answer their 404.
func TestAllowedMethods_NilKeepsEveryAnswer(t *testing.T) {
	forwarded := 0
	h := allowedMethodsHandler(t, nil, &forwarded)
	if rec := serveBFF(h, http.MethodGet, "/bff/api/v1/auth/login", false); rec.Code != http.StatusForbidden || rec.Header().Get("Allow") != "" {
		t.Fatalf("GET without the proof: %d Allow=%q; want 403", rec.Code, rec.Header().Get("Allow"))
	}
	if rec := serveBFF(h, http.MethodGet, "/bff/api/v1/auth/login", true); rec.Code != http.StatusNoContent || forwarded != 1 {
		t.Fatalf("GET with the proof: %d, forwarded %d; want 204, 1", rec.Code, forwarded)
	}
	for _, p := range []string{RefreshPath, LogoutPath} {
		rec := serveBFF(h, http.MethodGet, p, true)
		if rec.Code != http.StatusNotFound || rec.Header().Get("Allow") != "" ||
			rec.Body.String() != `{"error":"`+destinationRefusedErr+`"}` {
			t.Errorf("GET %s: %d Allow=%q %s; want the 404 %s", p, rec.Code, rec.Header().Get("Allow"), rec.Body, destinationRefusedErr)
		}
	}
}
