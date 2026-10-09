package runtime

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Shutdown waits for the mail sent after a response before it closes the
// pool; when its budget ends first it says so instead of cutting it off
// silently.
func TestShutdown_WaitsForDetachedWorkAndNamesWhatItCutOff(t *testing.T) {
	var stderr bytes.Buffer
	r := &Runtime{cfg: Config{Stderr: &stderr}, detached: &service.DetachedWork{}}
	release := make(chan struct{})
	defer close(release)
	r.detached.Run(context.Background(), func(context.Context) { <-release })

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	_ = r.Shutdown(expired)
	if !strings.Contains(stderr.String(), "background work still running") || !strings.Contains(stderr.String(), "back-channel logout delivery") {
		t.Errorf("stderr = %q; want the cut-off background work named", stderr.String())
	}
}
