package runtime

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// OSS-HARDEN-1 item 1: the end-session back-channel deliveries run on the
// runtime's detached work, so Shutdown waits for one that is still running
// before it closes the pool. Driven through buildDeps against the test
// database: a delivery held open keeps Shutdown from returning, and Shutdown
// returns only after it finished.
func TestShutdown_WaitsForARunningLogoutDelivery(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	rt, err := New(Config{Addr: "127.0.0.1:0", Issuer: "http://localhost", JWKSDBURL: dbURL,
		DataDir: t.TempDir(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	deps, pool, _, _, _, _, _, _, _, _, _, _, err := rt.buildDeps(context.Background(), lifecycle.NewStartupReport())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	defer pool.Close()
	if deps.Background == nil {
		t.Fatal("the runtime hands the router no background runner for the end-session deliveries")
	}
	release, started := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	deps.Background(context.Background(), func(context.Context) {
		close(started)
		<-release
		finished.Store(true)
	})
	<-started

	returned := make(chan struct{})
	go func() {
		_ = rt.Shutdown(context.Background())
		close(returned)
	}()
	// A delivery that is not counted lets Shutdown return at once; a counted
	// one holds it until the delivery ends, however long this waits.
	select {
	case <-returned:
		close(release)
		t.Fatal("Shutdown returned while a logout delivery was still running")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return after the delivery ended")
	}
	if !finished.Load() {
		t.Fatal("Shutdown returned before the delivery finished")
	}
}
