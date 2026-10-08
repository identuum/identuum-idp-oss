package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OSS-PRE-RELEASE-FIXES (review F5): devseed's errors carry the HTTP status
// and the response's error code only. A response body is never excerpted
// into an error, so a credential inside a malformed or unexpected answer
// cannot reach stderr (devseed-live keeps that stderr in seed*.err).
const errSentinel = "SENTINEL-not-a-real-secret-7Q2"

func TestErrors_NeverCarryTheResponseBody(t *testing.T) {
	t.Run("an error answer gives its error code and nothing else", func(t *testing.T) {
		got := truncate([]byte(`{"error":"invalid_request","client_secret":"` + errSentinel + `"}`))
		if strings.Contains(got, errSentinel) || got != "error=invalid_request" {
			t.Errorf("truncate: sentinel present %v, %d bytes; want exactly error=invalid_request",
				strings.Contains(got, errSentinel), len(got))
		}
	})
	t.Run("a malformed or unknown body gives its size only", func(t *testing.T) {
		for _, body := range []string{`{"secret":"` + errSentinel, errSentinel, `{"error":"` + errSentinel + `"}`} {
			got := truncate([]byte(body))
			if strings.Contains(got, errSentinel) || !strings.HasPrefix(got, "body withheld") {
				t.Errorf("truncate(%d-byte body): sentinel present %v; want a withheld-body note",
					len(body), strings.Contains(got, errSentinel))
			}
		}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login/mfa/enroll/initiate":
			// a truncated answer that still carries the secret's prefix
			_, _ = io.WriteString(w, `{"secret":"`+errSentinel)
		case "/api/v1/clients":
			w.WriteHeader(http.StatusCreated)
			// a changed envelope: the secret without a recognised client_id
			_, _ = io.WriteString(w, `{"credential":{"id":"c-1"},"client_secret":"`+errSentinel+`"}`)
		}
	}))
	defer srv.Close()

	t.Run("enrolment with a malformed secret answer", func(t *testing.T) {
		_, _, err := enrolMFA(srv.URL, "00000000-0000-7000-0000-000000000001")
		if err == nil || strings.Contains(err.Error(), errSentinel) {
			t.Fatalf("enrolMFA error carries the response body (or is nil): %v", err != nil)
		}
	})
	t.Run("client creation with an envelope that has no client_id", func(t *testing.T) {
		_, err := ensureClient(srv.URL, "bearer", "org-1", "a@b.test", "pw")
		if err == nil || strings.Contains(err.Error(), errSentinel) {
			t.Fatalf("ensureClient error carries the response body (or is nil): %v", err != nil)
		}
	})
}
