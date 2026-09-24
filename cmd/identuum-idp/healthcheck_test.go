package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The distroless image has no shell and no curl, so a Docker healthcheck
// must be the binary asking its own /healthz: 0 when it answers 200, 1
// otherwise — including nothing listening.
func TestHealthcheck_ExitsZeroOnlyWhenHealthzAnswers200(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	if code := run([]string{"healthcheck", srv.URL}, &out, &errOut); code != 0 {
		t.Fatalf("healthcheck against a healthy /healthz = %d (%s), want 0", code, errOut.String())
	}
	status = http.StatusServiceUnavailable
	if code := run([]string{"healthcheck", srv.URL}, &out, &errOut); code != 1 {
		t.Fatalf("healthcheck against a 503 /healthz = %d, want 1", code)
	}

	// Nothing listening: a port that was bound and released.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	_ = ln.Close()
	if code := run([]string{"healthcheck", dead}, &out, &errOut); code != 1 {
		t.Fatalf("healthcheck with nothing listening = %d, want 1", code)
	}
}

// With no URL, the probe targets this container's own listen address, as
// the appliance resolves it, on loopback when it binds every interface.
func TestHealthcheckTarget_FollowsTheApplianceListenAddress(t *testing.T) {
	for _, tc := range []struct{ listen, oss, want string }{
		{"", "", "http://127.0.0.1:7113/healthz"},
		{"", "0.0.0.0:7113", "http://127.0.0.1:7113/healthz"},
		{"0.0.0.0:8000", "0.0.0.0:7113", "http://127.0.0.1:8000/healthz"},
		{"127.0.0.1:9000", "", "http://127.0.0.1:9000/healthz"},
		{"[::]:7113", "", "http://127.0.0.1:7113/healthz"},
	} {
		t.Setenv("IDENTUUM_IDP_LISTEN", tc.listen)
		t.Setenv("IDENTUUM_IDP_OSS_LISTEN", tc.oss)
		if got := healthcheckTarget(""); got != tc.want {
			t.Errorf("listen=%q oss=%q: target %q, want %q", tc.listen, tc.oss, got, tc.want)
		}
	}
}
