package lease

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestNewInstanceID_UUIDComponentIsV7 pins the identifiers-are-v7 convention
// at what was the last ad-hoc v4 identifier site outside tests: the lease
// instance identity's uuid component is a UUIDv7 (time-ordered, minted
// v7-first through uuidgen), with plain v4 reserved for documented
// unpredictability sites (the WebAuthn dummy material) and RNG-failure
// fallbacks. Under a working RNG — every test run — the component MUST be v7.
// RULE: IDENTIFIER-UUIDV7-1
func TestNewInstanceID_UUIDComponentIsV7(t *testing.T) {
	id := NewInstanceID()
	slash := strings.LastIndex(id, "/")
	if slash < 1 || slash == len(id)-1 {
		t.Fatalf("instance id must be <hostname>/<uuid>, got %q", id)
	}
	u, err := uuid.Parse(id[slash+1:])
	if err != nil {
		t.Fatalf("instance id uuid component must parse: %v (id %q)", err, id)
	}
	if u.Version() != 7 {
		t.Errorf("instance id uuid component must be UUIDv7 (identifiers are v7, time-ordered); got version %d in %q", u.Version(), id)
	}
}
