package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// OSS-PRE-RELEASE-FIXES (review F2): the right secret must get ONE known
// post-authentication answer — a bogus authorization code refused with 400
// invalid_grant — and nothing else passes: not a server failure, not a
// malformed body, not another refusal.
func TestClientAuthCheck_OnlyTheKnownAnswerPasses(t *testing.T) {
	const id, secret = "client-1", "right-secret"
	cases := []struct {
		name     string
		status   int
		body     string
		wantPass bool
	}{
		{"400 invalid_grant: authenticated, then the bogus code refused", http.StatusBadRequest, `{"error":"invalid_grant"}`, true},
		{"503 from a failing store", http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, false},
		{"500 with no body", http.StatusInternalServerError, ``, false},
		{"400 with a malformed body", http.StatusBadRequest, `{"error":`, false},
		{"400 with another error", http.StatusBadRequest, `{"error":"unsupported_grant_type"}`, false},
		{"200 for a bogus code", http.StatusOK, `{"access_token":"x"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, pass, ok := r.BasicAuth(); !ok || pass != secret {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			err := clientAuthCheck(srv.URL, id, secret)
			if (err == nil) != tc.wantPass {
				t.Fatalf("clientAuthCheck passed=%v; want passed=%v (%v)", err == nil, tc.wantPass, err)
			}
		})
	}
}
