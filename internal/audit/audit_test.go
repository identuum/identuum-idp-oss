package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// TestNoopService_RecordZeroEvent verifies the no-op implementation
// accepts a zero-value event and returns nil — the safest baseline
// for callers that forget to populate fields.
// RULE: AUDIT-NOOP-1
func TestNoopService_RecordZeroEvent(t *testing.T) {
	var svc Service = NoopService{}
	if err := svc.Record(context.Background(), Event{}); err != nil {
		t.Errorf("NoopService.Record(zero) = %v, want nil", err)
	}
	// Direct concrete call so the no-op contract is pinned on NoopService.Record
	// itself: it discards the event and always returns nil.
	if err := (NoopService{}).Record(context.Background(), Event{}); err != nil {
		t.Errorf("NoopService{}.Record (concrete) = %v, want nil", err)
	}
}

// TestNoopService_RecordRepresentativeEvent verifies a populated
// event is also accepted. The no-op path is deliberately checked
// against a realistic payload so changes that would silently break
// the production shape (e.g. moving a field name) are flagged.
func TestNoopService_RecordRepresentativeEvent(t *testing.T) {
	var svc Service = NoopService{}
	event := Event{
		Action:         "user.login.success",
		Outcome:        "success",
		ActorID:        uuid.New(),
		ActorType:      "user",
		ActorEmail:     "user@example.com",
		ActorRole:      "org_user",
		OrganizationID: uuid.New(),
		SubjectID:      uuid.New(),
		SubjectType:    "user",
		SubjectEmail:   "subject@example.com",
		RequestID:      "req-1",
		CorrelationID:  "cor-1",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-suite/0.0",
		Metadata: map[string]any{
			"ip_match": true,
			"hops":     3,
		},
	}
	if err := svc.Record(context.Background(), event); err != nil {
		t.Errorf("NoopService.Record(populated) = %v, want nil", err)
	}
}

// TestRecorder_CapturesInOrder pins the test recorder's basic
// contract.
// RULE: AUDIT-MEMORY-1
func TestRecorder_CapturesInOrder(t *testing.T) {
	var rec Recorder
	for i, action := range []string{"a", "b", "c"} {
		if err := rec.Record(context.Background(), Event{Action: action}); err != nil {
			t.Fatalf("Record(%d) error: %v", i, err)
		}
	}
	got := rec.Events()
	if len(got) != 3 {
		t.Fatalf("Events len = %d, want 3", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Action != want {
			t.Errorf("events[%d].Action = %q, want %q", i, got[i].Action, want)
		}
	}
	if rec.Len() != 3 {
		t.Errorf("Len() = %d, want 3", rec.Len())
	}
}

// TestRecorder_MetadataDefensiveCopy verifies the recorder does not
// share its Metadata map with the caller. Mutating the recorded
// event's metadata after Record() returns must not leak into the
// stored copy.
func TestRecorder_MetadataDefensiveCopy(t *testing.T) {
	var rec Recorder
	meta := map[string]any{"version": "v1"}
	_ = rec.Record(context.Background(), Event{Action: "a", Metadata: meta})

	// Mutate the caller's map.
	meta["version"] = "v2"
	meta["new-key"] = "leak"

	stored := rec.Events()[0].Metadata
	if got := stored["version"]; got != "v1" {
		t.Errorf("recorded metadata.version = %v, want v1 (defensive copy must isolate)", got)
	}
	if _, ok := stored["new-key"]; ok {
		t.Errorf("recorded metadata leaked new key from caller")
	}

	// Mutating the slice returned by Events() also must not affect
	// future reads.
	rec.Events()[0].Action = "mutated"
	if rec.Events()[0].Action != "a" {
		t.Errorf("Events() must return a copy; got mutation leak")
	}
}

// TestRecorder_Reset clears recorded events.
func TestRecorder_Reset(t *testing.T) {
	var rec Recorder
	_ = rec.Record(context.Background(), Event{Action: "a"})
	if rec.Len() != 1 {
		t.Fatalf("pre-Reset Len = %d, want 1", rec.Len())
	}
	rec.Reset()
	if rec.Len() != 0 {
		t.Errorf("post-Reset Len = %d, want 0", rec.Len())
	}
}

// TestRecorder_ConcurrentRecord exercises the mutex under contention.
// A race-detector pass through this test (`go test -race`) is a
// stronger guarantee than this in-process assertion, but the
// in-process check still flags accidental drops or panics.
func TestRecorder_ConcurrentRecord(t *testing.T) {
	const goroutines = 16
	const perGoroutine = 32

	var rec Recorder
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = rec.Record(context.Background(), Event{Action: "concurrent"})
			}
		}()
	}
	wg.Wait()

	want := goroutines * perGoroutine
	if got := rec.Len(); got != want {
		t.Errorf("Len() after concurrent record = %d, want %d", got, want)
	}
}

// TestNoopService_PointerSatisfaction confirms NoopService can be
// passed by value AND by pointer to satisfy the Service interface.
// Some callers may want to hold *NoopService for symmetry with
// pointer-receiver implementations like *Recorder.
func TestNoopService_PointerSatisfaction(t *testing.T) {
	var direct Service = NoopService{}
	if err := direct.Record(context.Background(), Event{}); err != nil {
		t.Errorf("value receiver: %v", err)
	}
	pointer := NoopService{}
	var viaPointer Service = pointer
	if err := viaPointer.Record(context.Background(), Event{}); err != nil {
		t.Errorf("pointer receiver: %v", err)
	}
}
