package lease

import "testing"

// TestConfig_UnsetAcquireWindowGetsTheDefault pins the P0 found standing the
// dev stack up by hand.
//
// withDefaults tested AcquireWindow with `< 0` while TTL, Heartbeat and
// RetryInterval all used `<= 0`. An UNSET AcquireWindow is the zero value, not
// a negative, so it alone never received its default — and the production call
// site in internal/runtime constructs Config{InstanceID: ...} and nothing
// else, precisely to get defaults.
//
// The effect is the documented recovery guarantee silently inverted. The
// package comment promises "AcquireWindow 60s / RetryInterval 3s: a starting
// instance retries for 60s before refusing. 60s > TTL (45s), so even when the
// outgoing instance dies without releasing, the new one still acquires within
// the window once the stale lease lapses." With the window at zero it checks
// ONCE and gives up:
//
//	WARN single-replica lease held by another instance (...); retrying for up to 0s
//	ERROR NOT-SERVING: could not acquire the single-replica instance lease after 0s
//
// and because P-018 keeps the process alive rather than exiting, nothing ever
// retries: the instance serves 503 FOREVER. Any restart where the previous
// process did not release cleanly — a crash, a kill, a container recreate —
// leaves the service permanently down instead of recovering after the TTL.
// Observed live: 503 on /health and discovery for 60+ seconds after a rebuild,
// with no self-heal.
func TestConfig_UnsetAcquireWindowGetsTheDefault(t *testing.T) {
	t.Parallel()

	got := Config{InstanceID: "i-1"}.withDefaults()

	// CONTROL: the siblings must already default, or this test is measuring a
	// broken normaliser rather than the one-field gap it is about.
	if got.TTL != DefaultTTL || got.Heartbeat != DefaultHeartbeat || got.RetryInterval != DefaultRetryInterval {
		t.Fatalf("CONTROL FAILED: sibling defaults did not apply (TTL=%v Heartbeat=%v RetryInterval=%v)",
			got.TTL, got.Heartbeat, got.RetryInterval)
	}

	if got.AcquireWindow != DefaultAcquireWindow {
		t.Fatalf("unset AcquireWindow = %v, want the %v default — a starting instance that meets a "+
			"stale lease gives up immediately and stays NOT-SERVING (503) forever, because P-018 "+
			"keeps the process alive and nothing retries", got.AcquireWindow, DefaultAcquireWindow)
	}
	if got.AcquireWindow <= got.TTL {
		t.Fatalf("AcquireWindow %v must exceed TTL %v or a dead incumbent's lease never lapses "+
			"inside the window", got.AcquireWindow, got.TTL)
	}
}
