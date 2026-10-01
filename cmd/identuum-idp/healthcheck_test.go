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
// otherwise — including nothing listening. The store probe /readyz answers
// 200 here (store up); healthcheck_store_test.go covers it answering 503.
func TestHealthcheck_ExitsZeroOnlyWhenHealthzAnswers200(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(status)
		case "/readyz":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
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
		{":7113", "", "http://127.0.0.1:7113/healthz"},
		// IPv6 (D-020): "[::]" listens on IPv6 and is IPv4-reachable only
		// where the OS gives a dual-stack socket, so the probe uses [::1],
		// which an IPv6 wildcard always answers; a literal is dialled as is.
		{"[::]:7113", "", "http://[::1]:7113/healthz"},
		{"[::1]:7113", "", "http://[::1]:7113/healthz"},
		{"[2001:db8::5]:7113", "", "http://[2001:db8::5]:7113/healthz"},
	} {
		t.Setenv("IDENTUUM_IDP_LISTEN", tc.listen)
		t.Setenv("IDENTUUM_IDP_OSS_LISTEN", tc.oss)
		if got := healthcheckTarget(""); got != tc.want {
			t.Errorf("listen=%q oss=%q: target %q, want %q", tc.listen, tc.oss, got, tc.want)
		}
	}
}
