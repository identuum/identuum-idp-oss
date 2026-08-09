// Package lifecycle holds the process-lifecycle primitives that realize
// the P-018 NOT-SERVING-JUST-ALERTING rule
// (wiki/platform/process-lifecycle-rule.md): instead of a sub-application
// terminating its own process on a fatal startup/wiring condition
// (panic/log.Fatal/os.Exit), construction records a typed fault into a
// StartupReport, the process stays alive, the health probe reports the
// fault, and normal traffic is refused with 503.
//
// This package is a leaf: it imports nothing from internal/api,
// internal/handlers, or internal/runtime, so all three may depend on it
// without an import cycle.
package lifecycle

import (
	"sync"
	"sync/atomic"
)

// Severity classifies how a recorded fault affects serving.
type Severity string

const (
	// SeverityFatal means the sub-application cannot serve safely: the
	// process enters NOT-SERVING (every normal route returns 503) until it
	// is restarted into a healthy configuration. Used for missing/invalid
	// components on the authentication, token, session, or revocation path.
	SeverityFatal Severity = "fatal"

	// SeverityDegraded means an optional surface is partially unavailable
	// but the process can still serve the rest of its API. Health reports
	// the gap; the process keeps serving.
	SeverityDegraded Severity = "degraded"
)

// Fault is a single recorded startup/wiring fault. Reason MUST be
// human-readable and secret-free (no DB URL, password, token, or setup
// code material) per the P-018 security corollary.
type Fault struct {
	Component string   `json:"component"`
	Severity  Severity `json:"severity"`
	Reason    string   `json:"reason"`
}

// StartupReport accumulates typed faults during dependency construction
// and route registration. It is the single source of truth for the
// runtime serving mode: a report with no fatal fault is "serving"; one
// or more fatal faults puts the process in NOT-SERVING.
//
// All methods are nil-receiver-safe so callers on test/scaffold paths
// that never wire a report need no special-casing: Add is a no-op,
// HasFatal/Serving report the healthy default, and Faults returns nil.
//
// The hot-path predicate HasFatal is a lock-free atomic read so the
// per-request NOT-SERVING guard stays cheap. The faults slice itself is
// guarded by a mutex for the (rare) /health rendering path.
type StartupReport struct {
	mu       sync.RWMutex
	faults   []Fault
	hasFatal atomic.Bool
}

// NewStartupReport returns an empty, serving report.
func NewStartupReport() *StartupReport { return &StartupReport{} }

// Add records a fault. Nil-receiver-safe.
func (r *StartupReport) Add(component string, sev Severity, reason string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.faults = append(r.faults, Fault{Component: component, Severity: sev, Reason: reason})
	r.mu.Unlock()
	if sev == SeverityFatal {
		r.hasFatal.Store(true)
	}
}

// Fatal records a fatal fault (convenience for Add with SeverityFatal).
func (r *StartupReport) Fatal(component, reason string) {
	r.Add(component, SeverityFatal, reason)
}

// Degraded records a non-fatal fault (convenience for Add with
// SeverityDegraded).
func (r *StartupReport) Degraded(component, reason string) {
	r.Add(component, SeverityDegraded, reason)
}

// HasFatal reports whether any fatal fault has been recorded. Lock-free
// atomic read. Nil-receiver-safe (returns false).
func (r *StartupReport) HasFatal() bool {
	if r == nil {
		return false
	}
	return r.hasFatal.Load()
}

// Serving is the mode predicate: a report with no fatal fault is serving.
// Nil-receiver-safe (returns true).
func (r *StartupReport) Serving() bool { return !r.HasFatal() }

// HasAny reports whether any fault (fatal or degraded) is present.
// Nil-receiver-safe (returns false).
func (r *StartupReport) HasAny() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.faults) > 0
}

// Faults returns a copy of the recorded faults in insertion order.
// Nil-receiver-safe (returns nil).
func (r *StartupReport) Faults() []Fault {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.faults) == 0 {
		return nil
	}
	out := make([]Fault, len(r.faults))
	copy(out, r.faults)
	return out
}
