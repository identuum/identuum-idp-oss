package runtime

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// IPv4 is the default everywhere; IPv6 is supported and opt-in (owner ruling
// 2026-10-01, D-020). An empty host or 0.0.0.0 listens on IPv4 only; "[::]"
// listens on IPv6 (dual-stack where the OS allows); an IPv6 literal listens on
// that address only.

func TestListenNetwork(t *testing.T) {
	for addr, want := range map[string]string{
		":7113":          "tcp4",
		"0.0.0.0:7113":   "tcp4",
		"127.0.0.1:9090": "tcp4",
		"[::]:7113":      "tcp",
		"[::1]:7113":     "tcp",
		"localhost:7113": "tcp",
		"not-an-address": "tcp",
	} {
		if got := listenNetwork(addr); got != want {
			t.Errorf("listenNetwork(%q) = %q, want %q", addr, got, want)
		}
	}
}

// requireIPv6Loopback fails (never skips) when the host has no IPv6 loopback:
// the IPv6 rule cannot be proved without it.
func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("no IPv6 loopback on this host (%v): the IPv6 listen rule cannot be proved here", err)
	}
	_ = l.Close()
}

func reachable(t *testing.T, host, port string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func startMetricsOn(t *testing.T, addr string) string {
	t.Helper()
	r := &Runtime{cfg: Config{MetricsAddr: addr, Stdout: io.Discard, Stderr: io.Discard}}
	r.startMetricsListener()
	if r.metricsListener == nil {
		t.Fatalf("MetricsAddr %q bound no listener", addr)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.metricsSrv.Shutdown(ctx)
	})
	_, port, err := net.SplitHostPort(r.metricsListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}

func TestListenFamily_OverIPv6Loopback(t *testing.T) {
	requireIPv6Loopback(t)
	cases := []struct {
		addr   string
		v4, v6 bool
	}{
		{"0.0.0.0:0", true, false},   // the default form: IPv4 only
		{":0", true, false},          // an empty host: IPv4 only
		{"127.0.0.1:0", true, false}, // an IPv4 literal: that address
		{"[::1]:0", false, true},     // an IPv6 literal: that address only
	}
	for _, c := range cases {
		port := startMetricsOn(t, c.addr)
		if got := reachable(t, "127.0.0.1", port); got != c.v4 {
			t.Errorf("%s: reachable on 127.0.0.1 = %v, want %v", c.addr, got, c.v4)
		}
		if got := reachable(t, "::1", port); got != c.v6 {
			t.Errorf("%s: reachable on [::1] = %v, want %v", c.addr, got, c.v6)
		}
	}
	// "[::]": IPv6, and IPv4 too where the OS gives a dual-stack socket.
	port := startMetricsOn(t, "[::]:0")
	if !reachable(t, "::1", port) {
		t.Errorf("[::]: not reachable on [::1]")
	}
}
