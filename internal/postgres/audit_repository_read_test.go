package postgres

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/handlers"
)

// Compile-time proof that the pgx audit repo satisfies the handlers read seam.
var _ handlers.AuditReader = (*PgxAuditRepository)(nil)

// TEETH 5: a limit above the cap is clamped DOWN, not honoured; a non-positive
// limit becomes the default. This is the page-size policy the read API sets.
func TestClampAuditLimit(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, AuditListDefaultLimit},
		{-5, AuditListDefaultLimit},
		{1, 1},
		{50, 50},
		{200, 200},
		{201, AuditListMaxLimit},
		{100000, AuditListMaxLimit},
	}
	for _, c := range cases {
		if got := ClampAuditLimit(c.in); got != c.want {
			t.Fatalf("ClampAuditLimit(%d) = %d, want %d (a caller must not obtain an unbounded page)", c.in, got, c.want)
		}
	}
}
