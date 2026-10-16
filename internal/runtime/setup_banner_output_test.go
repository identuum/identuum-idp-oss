package runtime

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// P-R2, owner decision 2026-10-16: ordinary boot logs contain the wizard
// URL and local support command, but only terminal stdout receives the code.
// There is no database-free banner seam at the base commit. These tests
// deliberately require the fix to extract the existing startup block as:
//
//	writeSetupBanner(io.Writer, *setup.SetupBanner, func(io.Writer) bool)
//
// Start must pass setupOutputIsTerminal as the check. The wiring test below
// keeps a correct but unused renderer from satisfying the output tests.
// This test-only commit is expected not to compile until that seam is added.
func TestSetupBootOutput_NonTTYDoesNotPrintCode(t *testing.T) {
	banner := syntheticSetupBanner(t)
	var stdout bytes.Buffer
	writeSetupBanner(&stdout, banner, setupTerminalCheck(t, &stdout, false))
	if strings.Contains(stdout.String(), banner.SetupToken) {
		t.Fatal("non-terminal boot output disclosed the synthetic setup code")
	}
}

func TestSetupBootOutput_NonTTYRetainsURLAndCommand(t *testing.T) {
	banner := syntheticSetupBanner(t)
	var stdout bytes.Buffer
	writeSetupBanner(&stdout, banner, setupTerminalCheck(t, &stdout, false))
	assertSetupHints(t, stdout.String(), banner)
}

func TestSetupBootOutput_TTYStillPrintsCode(t *testing.T) {
	banner := syntheticSetupBanner(t)
	var stdout bytes.Buffer
	writeSetupBanner(&stdout, banner, setupTerminalCheck(t, &stdout, true))
	if !strings.Contains(stdout.String(), banner.SetupToken) {
		t.Error("terminal boot output omitted the synthetic setup code")
	}
	assertSetupHints(t, stdout.String(), banner)
}

// The production check must examine the destination, not global os.Stdout,
// and must fail closed for log capture. A character device alone is not a
// terminal: /dev/null is the control for the logger's old Stat-mode heuristic.
func TestSetupBootOutput_TerminalCheckRejectsLogCapture(t *testing.T) {
	t.Run("buffer", func(t *testing.T) {
		if setupOutputIsTerminal(&bytes.Buffer{}) {
			t.Fatal("a capture buffer must not count as terminal stdout")
		}
	})
	t.Run("pipe", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal("could not create a test pipe")
		}
		defer reader.Close()
		defer writer.Close()
		if setupOutputIsTerminal(writer) {
			t.Fatal("a container/log-capture pipe must not count as terminal stdout")
		}
	})
	t.Run("character_device", func(t *testing.T) {
		device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal("could not open the null device")
		}
		defer device.Close()
		if setupOutputIsTerminal(device) {
			t.Fatal("the null character device must not count as terminal stdout")
		}
	})
	// Positive control: without it a detector that always answers false
	// passes every case above and hides the code from terminal operators.
	t.Run("controlling_terminal", func(t *testing.T) {
		tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
		if err != nil {
			t.Skip("no controlling terminal; run under script(1) to exercise this control")
		}
		defer tty.Close()
		if !setupOutputIsTerminal(tty) {
			t.Fatal("the controlling terminal must count as terminal stdout")
		}
	})
}

func TestSetupBootOutput_StartUsesGuardedRenderer(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "runtime.go", nil, 0)
	if err != nil {
		t.Fatal("could not parse runtime.go")
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "Start" {
			continue
		}
		calls := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetupToken" {
				t.Error("Start must not access the plaintext code outside the guarded renderer")
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "writeSetupBanner" {
				return true
			}
			calls++
			if len(call.Args) != 3 {
				t.Error("Start must pass stdout, the initialized banner, and the real terminal check")
				return true
			}
			for i, want := range []string{"r.cfg.Stdout", "banner", "setupOutputIsTerminal"} {
				var arg bytes.Buffer
				if err := format.Node(&arg, fset, call.Args[i]); err != nil || arg.String() != want {
					t.Errorf("startup banner argument %d must be %s", i, want)
				}
			}
			return true
		})
		if calls != 1 {
			t.Error("Start must call the guarded banner renderer exactly once")
		}
		return
	}
	t.Fatal("Runtime.Start was not found; re-derive the startup wiring test")
}

func syntheticSetupBanner(t *testing.T) *setup.SetupBanner {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal("could not generate a synthetic setup code")
	}
	return &setup.SetupBanner{
		SetupURL:        "https://setup.example.invalid/setup",
		SetupToken:      base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]),
		TokenFilePath:   "/synthetic-data/setup-token.txt",
		ShowCodeCommand: "/app/identuum-idp show-setup-code /synthetic-data",
	}
}

func setupTerminalCheck(t *testing.T, want io.Writer, terminal bool) func(io.Writer) bool {
	t.Helper()
	called := false
	t.Cleanup(func() {
		if !called {
			t.Error("banner renderer did not consult the terminal check")
		}
	})
	return func(got io.Writer) bool {
		called = true
		if got != want {
			t.Error("terminal check received a writer other than the banner's stdout")
		}
		return terminal
	}
}

func assertSetupHints(t *testing.T, output string, banner *setup.SetupBanner) {
	t.Helper()
	if !strings.Contains(output, banner.SetupURL) {
		t.Error("boot output omitted the setup URL")
	}
	if !strings.Contains(output, banner.ShowCodeCommand) {
		t.Error("boot output omitted the show-setup-code command hint")
	}
}
