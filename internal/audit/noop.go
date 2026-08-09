package audit

import "context"

// NoopService discards every event. It is the default OSS
// implementation and the safe fallback for any deployment that does
// not need an append-only audit ledger.
//
// Concurrency: NoopService has no state, so calls from any goroutine
// are safe by construction.
//
// The receiver is by value so callers can construct NoopService{}
// inline without ever taking an address.
type NoopService struct{}

// Compile-time assertion that NoopService satisfies Service.
var _ Service = NoopService{}

// Record always returns nil. The context and event are ignored.
func (NoopService) Record(_ context.Context, _ Event) error {
	return nil
}
