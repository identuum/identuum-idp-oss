package runtime

import (
	"bytes"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// announceStartupMode must surface a fatal startup fault LOUDLY at ERROR
// level on Stderr — one per-fault line + a NOT SERVING summary — and must
// never panic or exit (P-018). Serving() must report NOT-SERVING.
func TestAnnounceStartupMode_FatalEmitsErrorLog(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("announceStartupMode panicked: %v", rec)
		}
	}()

	var buf bytes.Buffer
	report := lifecycle.NewStartupReport()
	report.Fatal("clients-routes",
		"clients management surface unavailable: neither ClientService nor ClientRepo is wired")

	r := &Runtime{cfg: Config{Stderr: &buf}, startupReport: report}
	r.announceStartupMode()

	out := buf.String()
	t.Logf("EVIDENCE ERROR log (stderr):\n%s", out)
	for _, want := range []string{"ERROR", "NOT SERVING", "clients-routes", "503"} {
		if !strings.Contains(out, want) {
			t.Errorf("ERROR log missing %q; got: %q", want, out)
		}
	}
	if r.Serving() {
		t.Errorf("Serving() must be false when a fatal fault is present")
	}
}

// A serving runtime (no fatal fault) must be silent and report Serving().
func TestAnnounceStartupMode_ServingIsSilent(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{cfg: Config{Stderr: &buf}, startupReport: lifecycle.NewStartupReport()}
	r.announceStartupMode()

	if buf.Len() != 0 {
		t.Errorf("serving runtime must not log a NOT-SERVING line: %q", buf.String())
	}
	if !r.Serving() {
		t.Errorf("Serving() must be true with no fatal fault")
	}
}
