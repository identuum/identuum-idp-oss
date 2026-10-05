package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// FUNC-M9 (audits/oss-functionality-2026-10-05.md): with the database
// unreachable at boot the bare binary printed "jwks-db pool open failed",
// exited 1 and stayed down after the database came back; the compose install
// crash-looped. P-018 asks for NOT-SERVING with the fault on /health. serve
// now waits for the database: the process stays up, /livez answers, /health
// answers 503 not_serving naming the database, every other route 503.
func TestRunServe_ADatabaseDownAtBootWaitsNotServing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := serveWaitContext
	serveWaitContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	defer func() { serveWaitContext = prev }()

	var mu sync.Mutex
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		// Nothing listens on port 1: the database is down.
		done <- runServe(addr, "http://"+addr, "postgres://u:dev-u-not-a-secret@127.0.0.1:1/db?sslmode=disable&connect_timeout=1",
			time.Hour, "", lockedWriter{&mu, &stdout}, lockedWriter{&mu, &stderr})
	}()

	get := func(path string) (int, map[string]any) {
		var res *http.Response
		for i := 0; i < 50; i++ {
			if res, err = http.Get("http://" + addr + path); err == nil {
				break
			}
			select {
			case code := <-done:
				t.Fatalf("serve returned %d with the database down; want it to wait", code)
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err != nil {
			t.Fatalf("GET %s: nothing answers on the listen address: %v", path, err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return res.StatusCode, body
	}
	if st, _ := get("/livez"); st != http.StatusOK {
		t.Errorf("/livez = %d; want 200 while waiting", st)
	}
	st, body := get("/health")
	if st != http.StatusServiceUnavailable || body["status"] != "not_serving" || !strings.Contains(strings.ToLower(asJSON(body["faults"])), "database") {
		t.Errorf("/health = %d %v; want 503 not_serving with a database fault", st, body)
	}
	if st, _ := get("/api/v1/organizations"); st != http.StatusServiceUnavailable {
		t.Errorf("a normal route = %d; want 503", st)
	}
	select {
	case code := <-done:
		t.Fatalf("serve returned %d with the database down; want it to wait", code)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop when its wait was cancelled")
	}
	mu.Lock()
	out := stdout.String() + stderr.String()
	mu.Unlock()
	if strings.Contains(out, "dev-u-not-a-secret") || strings.Contains(out, "postgres://") {
		t.Error("the database URL reached the output")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
