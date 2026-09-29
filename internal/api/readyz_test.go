package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// OSS-POLISH item 2: /healthz (and /health) answer 200 with the store down —
// they are liveness and read only the StartupReport. /readyz is the store
// probe the container healthcheck adds: 503 while the store does not answer
// a ping, 200 when it does. /healthz is unchanged either way.
func TestReadyz_ReflectsTheStore_HealthzStaysLiveness(t *testing.T) {
	var storeErr error
	engine := NewOSSEngine(OSSRouterDeps{
		Version:       "test-readyz",
		StartupReport: lifecycle.NewStartupReport(),
		ClientRepo:    stubClientRepo{},
		DBPinger:      func(context.Context) error { return storeErr },
	})

	storeErr = errors.New("connection refused")
	if code, body, _ := nsDo(engine, http.MethodGet, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("store down: /readyz = %d, want 503; body=%s", code, body)
	}
	if code, _, _ := nsDo(engine, http.MethodGet, "/healthz"); code != http.StatusOK {
		t.Fatalf("store down: /healthz = %d, want 200 (liveness)", code)
	}

	storeErr = nil
	if code, body, _ := nsDo(engine, http.MethodGet, "/readyz"); code != http.StatusOK {
		t.Fatalf("store up: /readyz = %d, want 200; body=%s", code, body)
	}
}
