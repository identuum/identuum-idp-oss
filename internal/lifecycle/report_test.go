package lifecycle

import "testing"

// A fatal fault trips NOT-SERVING; a degraded fault does not.
func TestStartupReport_FatalTripsNotServing(t *testing.T) {
	r := NewStartupReport()
	if !r.Serving() || r.HasFatal() {
		t.Fatalf("fresh report must be serving")
	}

	r.Degraded("admin-x", "optional surface down")
	if !r.Serving() {
		t.Errorf("a degraded fault must NOT trip NOT-SERVING")
	}
	if !r.HasAny() {
		t.Errorf("HasAny must be true after a degraded fault")
	}

	r.Fatal("bearer-auth", "verifier missing")
	if r.Serving() || !r.HasFatal() {
		t.Errorf("a fatal fault must trip NOT-SERVING")
	}
	faults := r.Faults()
	if len(faults) != 2 {
		t.Fatalf("Faults len = %d, want 2", len(faults))
	}
	if faults[1].Severity != SeverityFatal || faults[1].Component != "bearer-auth" {
		t.Errorf("unexpected fatal fault: %+v", faults[1])
	}
}

// Every method must be nil-receiver-safe so unwired test/scaffold paths
// need no special-casing — and, critically, must NEVER panic (P-018).
func TestStartupReport_NilReceiverSafe(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("nil *StartupReport method panicked: %v", rec)
		}
	}()
	var r *StartupReport // nil

	r.Add("c", SeverityFatal, "x")
	r.Fatal("c", "x")
	r.Degraded("c", "x")

	if r.HasFatal() {
		t.Errorf("nil report HasFatal must be false")
	}
	if !r.Serving() {
		t.Errorf("nil report Serving must be true")
	}
	if r.HasAny() {
		t.Errorf("nil report HasAny must be false")
	}
	if r.Faults() != nil {
		t.Errorf("nil report Faults must be nil")
	}
}
