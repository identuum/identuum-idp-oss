package runtime_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// countingListener counts how often the caller's listener is really closed.
type countingListener struct {
	net.Listener
	closes atomic.Int32
}

func (l *countingListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func listen(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	t.Cleanup(func() { _ = ln.Close() })
	return cl
}

func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func shutdown(t *testing.T, rt *runtime.Runtime) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return rt.Shutdown(ctx)
}

// OSS-SEAM-2 proof 1: listener ownership on every error path.
func TestNewWithListener_Ownership(t *testing.T) {
	quiet := func(k string) string { return "" }
	t.Run("a refused constructor leaves the listener open and the caller's", func(t *testing.T) {
		if _, err := runtime.NewWithListener(runtime.Options{}, nil); err == nil {
			t.Fatal("a nil listener must be refused")
		}
		ln := listen(t)
		if _, err := runtime.NewWithListener(runtime.Options{Addr: "127.0.0.1:1"}, ln); err == nil {
			t.Fatal("an Addr that is not the listener's must be refused")
		}
		if ln.closes.Load() != 0 || !dialable(ln.Addr().String()) {
			t.Fatalf("after a refused constructor the listener was closed %d time(s); it must stay open", ln.closes.Load())
		}
	})
	t.Run("a failed Start keeps it owned; Shutdown closes it once, also when called twice", func(t *testing.T) {
		ln := listen(t)
		rt, err := runtime.NewWithListener(runtime.Options{Stdout: io.Discard, Stderr: io.Discard, Getenv: quiet}, ln)
		if err != nil {
			t.Fatal(err)
		}
		if rt.Start(context.Background()) == nil {
			t.Fatal("Start without a database must fail")
		}
		if rt.Start(context.Background()) == nil {
			t.Fatal("a second Start without a database must fail too")
		}
		if ln.closes.Load() != 0 {
			t.Fatal("a failed Start closed the listener; Shutdown owns that")
		}
		if err := shutdown(t, rt); err != nil {
			t.Fatal(err)
		}
		if err := shutdown(t, rt); err != nil {
			t.Fatal(err)
		}
		if n := ln.closes.Load(); n != 1 {
			t.Fatalf("the listener was closed %d time(s); want exactly 1", n)
		}
	})
	t.Run("Shutdown before Start closes it once", func(t *testing.T) {
		ln := listen(t)
		rt, err := runtime.NewWithListener(runtime.Options{Getenv: quiet}, ln)
		if err != nil {
			t.Fatal(err)
		}
		_ = shutdown(t, rt)
		_ = shutdown(t, rt)
		if n := ln.closes.Load(); n != 1 || dialable(ln.Addr().String()) {
			t.Fatalf("closed %d time(s), still dialable %v; want 1 and no", n, dialable(ln.Addr().String()))
		}
	})
}

// OSS-SEAM-2 proof 2: the given listener is served, a second Start is
// refused without touching it, and Shutdown closes it exactly once.
func TestNewWithListener_ServesTheGivenListener(t *testing.T) {
	dsn := migratedTestDSN(t)
	ln := listen(t)
	rt, err := runtime.NewWithListener(runtime.Options{Issuer: "http://localhost:7113", DatabaseURL: dsn,
		DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard}, ln)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if rt.Addr() != ln.Addr().String() {
		t.Fatalf("Addr %q is not the given listener's %q", rt.Addr(), ln.Addr().String())
	}
	if code := get(t, ln.Addr().String(), "/health"); code != http.StatusOK {
		t.Fatalf("/health on the given listener answered %d", code)
	}
	if rt.Start(context.Background()) == nil {
		t.Fatal("a second Start must be refused")
	}
	if code := get(t, ln.Addr().String(), "/health"); code != http.StatusOK || ln.closes.Load() != 0 {
		t.Fatalf("after the refused second Start: /health %d, closes %d; want 200 and 0", code, ln.closes.Load())
	}
	if h := rt.Health(); !h.Serving || len(h.Faults) != 0 {
		t.Fatalf("a healthy runtime reports serving %v with %d fault(s)", h.Serving, len(h.Faults))
	}
	if err := shutdown(t, rt); err != nil {
		t.Fatal(err)
	}
	_ = shutdown(t, rt)
	if n := ln.closes.Load(); n != 1 || dialable(ln.Addr().String()) {
		t.Fatalf("closed %d time(s), still dialable %v; want 1 and no", n, dialable(ln.Addr().String()))
	}
}

// OSS-SEAM-2 proof 3: a fatal startup (a FIPS build required of a non-FIPS
// binary) leaves the runtime NOT-SERVING on the given listener — /health
// still answers, a normal route answers 503 — and Health names the fault
// without a URL, password or token.
func TestNewWithListener_FatalStartupKeepsHealthServed(t *testing.T) {
	dsn := migratedTestDSN(t)
	ln := listen(t)
	getenv := func(k string) string {
		if k == "IDENTUUM_IDP_REQUIRE_FIPS" {
			return "true"
		}
		return os.Getenv(k)
	}
	rt, err := runtime.NewWithListener(runtime.Options{Issuer: "http://localhost:7113", DatabaseURL: dsn,
		DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard, Getenv: getenv}, ln)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("a fatal fault is NOT-SERVING, not a Start error: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(t, rt) })
	// Whether the fault occurred is the server's answer, not Health's (the
	// value under test): a normal route answers 503 only when NOT-SERVING.
	switch code := get(t, ln.Addr().String(), "/api/v1/component"); code {
	case http.StatusServiceUnavailable:
	case http.StatusOK:
		t.Skip("this binary is a FIPS build, so the required-FIPS fault does not occur")
	default:
		t.Fatalf("a normal route answered %d during a fatal startup; want 503", code)
	}
	h := rt.Health()
	if h.Serving {
		t.Fatal("the server refuses normal traffic, but Health reports serving")
	}
	fatal := false
	for _, f := range h.Faults {
		fatal = fatal || (f.Fatal && f.Component != "" && f.Reason != "")
		for _, leak := range []string{dsn, "postgres://", "password", "eyJ"} {
			if strings.Contains(f.Reason, leak) || strings.Contains(f.Component, leak) {
				t.Errorf("fault %q carries forbidden text", f.Component)
			}
		}
	}
	if !fatal {
		t.Fatalf("NOT-SERVING with %d fault(s), none fatal with a component and a reason", len(h.Faults))
	}
	if code := get(t, ln.Addr().String(), "/health"); code == 0 {
		t.Fatal("/health is not served on the given listener during a fatal startup")
	}
}

func get(t *testing.T, addr, path string) int {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + path)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
