package audit

import (
	"context"
	"sync"
)

// Recorder captures every event passed to Record in a slice. Suited
// for tests that need to assert "the handler emitted this audit
// event"; not intended for production wiring.
//
// Recorder is safe for concurrent Record calls. Reading via Events()
// returns a copy of the underlying slice so the caller cannot mutate
// recorded state in place.
//
// Recorder is intentionally simple — no filtering, no error
// injection. Tests that need richer fakes should embed Recorder or
// implement Service directly.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// Compile-time assertion that *Recorder satisfies Service.
var _ Service = (*Recorder)(nil)

// Record appends a defensive copy of the event so subsequent mutation
// by the caller does not retroactively change the recorded state.
// Metadata is shallow-copied; callers that need deep isolation
// should marshal/unmarshal at the call site.
func (r *Recorder) Record(_ context.Context, event Event) error {
	if event.Metadata != nil {
		copied := make(map[string]any, len(event.Metadata))
		for k, v := range event.Metadata {
			copied[k] = v
		}
		event.Metadata = copied
	}
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
	return nil
}

// Events returns a copy of the recorded events in record order.
// Callers may inspect and mutate the returned slice freely without
// affecting the recorder's internal state.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

// Len returns the number of recorded events without copying the
// slice. Useful in `for len(r.Events()) < n` polling loops.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// Reset clears the recorded events. Safe to call concurrently with
// Record.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.events = nil
	r.mu.Unlock()
}
