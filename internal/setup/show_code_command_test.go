package setup

import (
	"os"
	"strings"
	"testing"
)

// The boot banner's re-display command names this binary by its own path: the
// image puts it at /app/identuum-idp with no PATH entry, so a bare
// "identuum-idp show-setup-code" does not run inside the container.
func TestShowCodeCommand_NamesTheRunningBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	got := showCodeCommand("/app/data")
	if got != exe+" show-setup-code /app/data" {
		t.Errorf("command = %q, want the running binary's path, then show-setup-code /app/data", got)
	}
	if strings.HasPrefix(got, "identuum-idp ") {
		t.Errorf("command names the binary bare: %q", got)
	}
}
