package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OSS-POLISH item 2: the container healthcheck stayed "healthy" with the
// database stopped because it asked only the liveness probe. It must also
// require the store probe (/readyz): unhealthy when the store is unreachable.
func TestHealthcheck_UnhealthyWhenTheStoreIsUnreachable(t *testing.T) {
	storeUp := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/readyz":
			if storeUp {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var out, errb bytes.Buffer
	if rc := runHealthcheck([]string{srv.URL}, &out, &errb); rc != 1 {
		t.Fatalf("store down: rc = %d, want 1 (stdout %q)", rc, out.String())
	}
	if !strings.Contains(errb.String(), "/readyz") {
		t.Fatalf("store down: stderr %q does not name /readyz", errb.String())
	}

	storeUp = true
	out.Reset()
	errb.Reset()
	if rc := runHealthcheck([]string{srv.URL}, &out, &errb); rc != 0 {
		t.Fatalf("store up: rc = %d, want 0 (stderr %q)", rc, errb.String())
	}
}
