package runtime

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
	"github.com/identuum/identuum-idp-oss/logger"
)

// P3-12 teeth: the OSS serving runtime no longer discards its logs.
// Two halves are proven here without a DB:
//
//  1. buildDeps threads serviceLogger() into the service Configs, so a
//     service-layer fail-closed ERROR (P1-4's breach signal) reaches the
//     package logger instead of a constructor-defaulted zap.NewNop().
//  2. Start's first act is logger.InitializeZapLogger(), under which a
//     previously-discarded SOC 2 Security site (the safehttp SSRF block)
//     actually emits, tagged category=security.
//
// Happy-path behaviour is unchanged: no levels moved, no lines added at
// call sites; tests and one-shot tools keep the init()-seeded nops.

// swapPackageLoggers replaces all five package loggers and registers a
// cleanup that restores the originals, so these tests cannot leak a live
// logger into the rest of the package's tests.
func swapPackageLoggers(t *testing.T) {
	t.Helper()
	origInfo, origWarn, origErr, origDbg, origSec :=
		logger.Info, logger.Warning, logger.Error, logger.Debug, logger.Security
	t.Cleanup(func() {
		logger.Info, logger.Warning, logger.Error, logger.Debug, logger.Security =
			origInfo, origWarn, origErr, origDbg, origSec
	})
}

// failingLoginAttemptStore simulates the P1-4 scenario: the risk backend
// cannot be consulted.
type failingLoginAttemptStore struct{}

func (failingLoginAttemptStore) CountAccountFailuresSince(context.Context, string, string, string, time.Time) (int, error) {
	return 0, errors.New("risk backend down")
}

func (failingLoginAttemptStore) CountDistinctAccountsFromIPSince(context.Context, string, string, time.Time) (int, error) {
	return 0, errors.New("risk backend down")
}

func (failingLoginAttemptStore) Insert(context.Context, *domain.LoginAttempt) error {
	return nil
}

func (failingLoginAttemptStore) DeleteOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// TestServiceLogger_FailClosedErrorReachesPackageLogger proves half 1:
// a LoginRiskService built exactly as buildDeps builds it — with
// serviceLogger() — emits the P1-4 fail-closed ERROR through the package
// logger. Reverting the fix (buildDeps not threading a logger ≡
// serviceLogger returning nil, which the constructor defaults to
// zap.NewNop()) makes the observer see nothing and this test FAIL.
func TestServiceLogger_FailClosedErrorReachesPackageLogger(t *testing.T) {
	swapPackageLoggers(t)
	core, observed := observer.New(zapcore.ErrorLevel)
	// Mirror the production baseLogger options (logger.go InitializeZapLogger):
	// AddCaller + AddCallerSkip(1). serviceLogger() applies AddCallerSkip(-1)
	// on top (P3-12 follow-up D4), so DIRECT zap calls from services resolve
	// to their true call site.
	logger.Error = logger.NewLogger(zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)), zapcore.ErrorLevel)

	svc := service.NewLoginRiskService(
		lifecycle.NewStartupReport(),
		failingLoginAttemptStore{},
		service.LoginRiskServiceOptions{Logger: serviceLogger()},
	)

	err := svc.Check(context.Background(), "user@example.invalid", "203.0.113.9", service.LoginRiskPurposePassword)
	if !errors.Is(err, service.ErrLoginRiskBackendUnavailable) {
		t.Fatalf("Check: want ErrLoginRiskBackendUnavailable, got %v", err)
	}

	entries := observed.FilterMessage("login_risk: backend unavailable; failing closed (login refused with 503)").All()
	if len(entries) == 0 {
		t.Fatalf("P1-4 fail-closed ERROR did not reach the package logger — the service-layer signal is dormant again (P3-12 regression)")
	}
	if entries[0].Level != zapcore.ErrorLevel {
		t.Fatalf("fail-closed signal level = %s, want ERROR", entries[0].Level)
	}
	// D4: the entry must attribute its caller inside the service that logged
	// it. (File-level only — with a miscalibrated skip the frame above is
	// ALSO in login_risk_service.go, so the decisive teeth are the exact
	// file:line probe in TestServiceLogger_CallerAttributionCalibrated.)
	if !entries[0].Caller.Defined || !strings.HasSuffix(entries[0].Caller.File, "login_risk_service.go") {
		t.Fatalf("fail-closed entry caller = %q, want a login_risk_service.go site (D4 caller-skip miscalibration)", entries[0].Caller.String())
	}
}

// TestServiceLogger_CallerAttributionCalibrated is D4's revert-proof teeth:
// a DIRECT zap call through serviceLogger() must attribute THIS file and
// THIS exact line. The package logger mirrors production options
// (AddCallerSkip(1), correct for the logger package's wrappers); without
// serviceLogger's AddCallerSkip(-1) the probe below is attributed one frame
// too high — the test harness, a different file — and this test goes RED.
func TestServiceLogger_CallerAttributionCalibrated(t *testing.T) {
	swapPackageLoggers(t)
	core, observed := observer.New(zapcore.ErrorLevel)
	logger.Error = logger.NewLogger(zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)), zapcore.ErrorLevel)

	lg := serviceLogger()
	_, wantFile, probeBase, _ := goruntime.Caller(0)
	lg.Error("caller calibration probe") // probeBase+1: the line the entry must attribute

	entries := observed.FilterMessage("caller calibration probe").All()
	if len(entries) != 1 {
		t.Fatalf("probe entries = %d, want 1", len(entries))
	}
	got := entries[0].Caller
	if !got.Defined || got.File != wantFile || got.Line != probeBase+1 {
		t.Fatalf("probe caller = %q, want %s:%d — serviceLogger caller-skip miscalibrated (D4 regression)",
			got.String(), wantFile, probeBase+1)
	}
}

// TestInitializeZapLogger_SecuritySSRFBlockEmits proves half 2: under the
// logger initialization Start now performs as its first act, the safehttp
// SSRF-block Security site — one of the two SOC 2 signals that were
// silently discarded — actually emits to stdout, tagged
// category=security. Reverting the fix (Start not initializing ≡ the
// init()-seeded nop loggers) produces no output and this test FAILS.
func TestInitializeZapLogger_SecuritySSRFBlockEmits(t *testing.T) {
	swapPackageLoggers(t)
	t.Setenv("AUTH_SERVICE_LOG_LEVEL", "info")

	// Capture stdout across the init: InitializeZapLogger binds its core to
	// the os.Stdout VALUE at call time, so the pipe must be in place first.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	// Exactly what Runtime.Start does first (P3-12).
	logger.InitializeZapLogger()

	// Drive the Security site: the safe client's dial control blocks
	// loopback before any packet is sent.
	client := safehttp.NewSafeClient()
	_, reqErr := client.Get("http://127.0.0.1:9/")
	if reqErr == nil {
		t.Fatalf("SSRF request to loopback unexpectedly succeeded")
	}

	_ = w.Close()
	out, readErr := io.ReadAll(r)
	os.Stdout = origStdout
	if readErr != nil {
		t.Fatalf("read captured stdout: %v", readErr)
	}

	if !strings.Contains(string(out), "BLOCKED SSRF ATTEMPT") {
		t.Fatalf("Security SSRF-block signal did not emit under the serving logger init — SOC 2 signal dormant again (P3-12 regression). Captured %d bytes", len(out))
	}
	if !strings.Contains(string(out), `"category":"security"`) {
		t.Fatalf("SSRF-block emitted without the SOC 2 category=security tag. Output: %.200s", string(out))
	}
}

// TestStart_CallsInitializeZapLoggerFirst pins the one-line init half of
// P3-12 structurally AND its ordering: Runtime.Start's body must contain a
// call to logger.InitializeZapLogger, and that call must PRECEDE the
// r.buildDeps(...) call. Ordering is load-bearing (P3-12 follow-up D3):
// serviceLogger() reads the package logger at buildDeps CALL time, so an
// init placed after buildDeps would hand every service the nop again while
// a presence-only pin stayed green. Parsed from the real AST (go/parser),
// not a substring match — this file names both functions, so a body grep
// would satisfy itself (standing lesson 8). Reverting the Start line OR
// moving it below buildDeps turns this RED.
func TestStart_CallsInitializeZapLoggerFirst(t *testing.T) {
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, "runtime.go", nil, 0)
	if err != nil {
		t.Fatalf("parse runtime.go: %v", err)
	}
	for _, decl := range astFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Start" || fn.Recv == nil {
			continue
		}
		var initPos, buildDepsPos token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "logger" && sel.Sel.Name == "InitializeZapLogger" && initPos == token.NoPos {
				initPos = call.Pos()
			}
			if sel.Sel.Name == "buildDeps" && buildDepsPos == token.NoPos {
				buildDepsPos = call.Pos()
			}
			return true
		})
		if initPos == token.NoPos {
			t.Fatalf("Runtime.Start no longer calls logger.InitializeZapLogger() — the serving process is log-silent again (P3-12 regression)")
		}
		if buildDepsPos == token.NoPos {
			t.Fatalf("Runtime.Start no longer calls buildDeps — test assumptions broken, re-derive")
		}
		if initPos >= buildDepsPos {
			t.Fatalf("logger.InitializeZapLogger() at %s does not PRECEDE r.buildDeps() at %s — services capture the nop logger at construction time (P3-12 follow-up D3 regression)",
				fset.Position(initPos), fset.Position(buildDepsPos))
		}
		return
	}
	t.Fatalf("Runtime.Start not found in runtime.go")
}

// TestServiceConfigs_LoggerFieldAlwaysThreaded pins the threading half of
// P3-12 structurally (follow-up D2): the earlier observer test built the
// service ITSELF with serviceLogger(), proving only that serviceLogger()
// returns a live logger — deleting every Logger: line in buildDeps left it
// green. This test DERIVES, from the internal/service AST, the set of
// Config/Options struct types carrying a `Logger *zap.Logger` field (never
// an enumerated type list — the P3-11 lesson), then walks every non-test
// file of THIS package and requires each composite literal of one of those
// types to set its Logger key. A new Logger-carrying Config, or a new
// construction site, is covered the day it appears; deleting one threading
// line goes RED naming the exact file:line.
func TestServiceConfigs_LoggerFieldAlwaysThreaded(t *testing.T) {
	fset := token.NewFileSet()

	// 1. Derive the Logger-carrying service struct set from internal/service.
	serviceTypes := map[string]bool{}
	svcFiles, err := filepath.Glob("../service/*.go")
	if err != nil || len(svcFiles) == 0 {
		t.Fatalf("glob internal/service: err=%v files=%d", err, len(svcFiles))
	}
	for _, f := range svcFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				star, ok := fld.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "zap" || sel.Sel.Name != "Logger" {
					continue
				}
				for _, name := range fld.Names {
					if name.Name == "Logger" {
						serviceTypes[ts.Name.Name] = true
					}
				}
			}
			return true
		})
	}
	if len(serviceTypes) < 5 {
		t.Fatalf("derived only %d Logger-carrying service types (%v) — derivation broken, re-check the parse", len(serviceTypes), serviceTypes)
	}

	// 2. Every service.<T>{...} literal in this package's non-test files,
	// where T is in the derived set, must set Logger.
	rtFiles, err := filepath.Glob("*.go")
	if err != nil || len(rtFiles) == 0 {
		t.Fatalf("glob runtime package: err=%v files=%d", err, len(rtFiles))
	}
	literalsSeen := 0
	var violations []string
	for _, f := range rtFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := cl.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "service" || !serviceTypes[sel.Sel.Name] {
				return true
			}
			literalsSeen++
			hasLogger := false
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Logger" {
					hasLogger = true
				}
			}
			if !hasLogger {
				violations = append(violations, fset.Position(cl.Pos()).String()+" service."+sel.Sel.Name)
			}
			return true
		})
	}
	if literalsSeen == 0 {
		t.Fatalf("found NO Logger-carrying service Config literals in the runtime package — derivation or walk broken, re-check")
	}
	if len(violations) > 0 {
		t.Fatalf("service Config literal(s) with a Logger field but no Logger set — the P3-12 threading is partially reverted:\n  %s", strings.Join(violations, "\n  "))
	}
}
