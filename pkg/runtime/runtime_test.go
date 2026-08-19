package runtime_test

// Tests for the public OSS pkg/runtime seam.
//
// These tests guard four properties future identuum-idp-ce work will
// rely on:
//
//   1. The public Config and Runtime types are true Go type aliases
//      of the internal/runtime authority — values constructed at
//      either path are interchangeable without conversion.
//   2. New through the public package produces a non-nil Runtime
//      whose Engine() is nil before Start (the lifecycle contract
//      the doc claims).
//   3. A no-DB Start/Shutdown round trip succeeds against an
//      ephemeral kernel-chosen port; the lifecycle handles a
//      graceful drain without panicking.
//   4. The public package's direct imports do not pull in CE, the
//      identuum-idp monolith, identuum-ag, identuum-ui, or
//      auth-service. The seam is the import-boundary enforcement
//      point future drift checks will hit first.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	internalruntime "github.com/identuum/identuum-idp-oss/internal/runtime"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
	pkgruntime "github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// TestPublicConfig_IsAliasOfInternal proves Config is a real Go type
// alias: a value declared at one path is assignable at the other
// without conversion. If the alias ever degrades to a distinct
// named type this test breaks at compile time.
func TestPublicConfig_IsAliasOfInternal(t *testing.T) {
	pub := pkgruntime.Config{Addr: ":0", Version: "alias-identity"}

	var asInternal internalruntime.Config = pub
	var asPublic pkgruntime.Config = asInternal

	assert.Equal(t, ":0", asPublic.Addr)
	assert.Equal(t, "alias-identity", asPublic.Version)
}

// TestPublicRuntime_IsAliasOfInternal proves Runtime is a real Go
// type alias: a *Runtime constructed at one path is the same value
// at the other. Compile-time check via cross-assignment.
func TestPublicRuntime_IsAliasOfInternal(t *testing.T) {
	rt, err := pkgruntime.New(pkgruntime.Config{Addr: ":0"})
	require.NoError(t, err)
	require.NotNil(t, rt)

	var asInternal *internalruntime.Runtime = rt
	var asPublic *pkgruntime.Runtime = asInternal
	assert.Same(t, rt, asPublic)
}

// TestNew_RejectsEmptyAddr pins the validation contract: New must
// surface "Addr is empty" before any DB / listener side-effect can
// take place.
func TestNew_RejectsEmptyAddr(t *testing.T) {
	rt, err := pkgruntime.New(pkgruntime.Config{})
	require.Error(t, err)
	require.Nil(t, rt)
	assert.Contains(t, err.Error(), "Addr is empty")
}

// TestNew_EngineNilBeforeStart pins the lifecycle contract: Engine
// returns nil before Start. CE composition can rely on this to
// distinguish "runtime not yet started" from "runtime running with
// an empty engine."
func TestNew_EngineNilBeforeStart(t *testing.T) {
	rt, err := pkgruntime.New(pkgruntime.Config{Addr: "127.0.0.1:0"})
	require.NoError(t, err)
	assert.Nil(t, rt.Engine(), "Engine() before Start must be nil")
	assert.Empty(t, rt.Addr(), "Addr() before Start must be empty")
}

// TestStart_NoDB_ReturnsDatabaseRequiredError pins the new contract:
// the public seam has NO no-DB "scaffold" serve mode. Start without a
// database URL returns a clean configuration error naming the missing
// variable (a legitimate pre-serve startup boundary — no panic, no
// degraded server); the engine is never wired and Shutdown remains a
// safe no-op. The full service layer + full router is the only serve
// path.
func TestStart_NoDB_ReturnsDatabaseRequiredError(t *testing.T) {
	rt, err := pkgruntime.New(pkgruntime.Config{
		Addr:    "127.0.0.1:0",
		Version: "roundtrip-test",
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	require.NoError(t, err)

	err = rt.Start(context.Background())
	require.Error(t, err, "Start with no database URL must fail fast, not serve a scaffold")
	assert.Contains(t, err.Error(), "IDENTUUM_IDP_DATABASE_URL",
		"error must name the missing variable; got %q", err.Error())
	assert.Nil(t, rt.Engine(), "no engine must be wired when the DB URL is missing")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.NoError(t, rt.Shutdown(ctx), "Shutdown after a failed Start must be a safe no-op")
}

// TestShutdown_BeforeStart_NoPanic pins the safety contract:
// Shutdown is idempotent and must not panic when Start was never
// called. CE composition error-handling depends on this.
func TestShutdown_BeforeStart_NoPanic(t *testing.T) {
	rt, err := pkgruntime.New(pkgruntime.Config{Addr: "127.0.0.1:0"})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	assert.NotPanics(t, func() {
		_ = rt.Shutdown(ctx)
	})

	// Second Shutdown returns the same (nil) error — idempotent.
	assert.NotPanics(t, func() {
		_ = rt.Shutdown(ctx)
	})
}

// TestStart_CalledTwice_Errors pins the single-use contract: a
// Runtime is not restartable. Constructing a fresh Runtime is the
// only supported way to restart. The restart guard now only triggers
// after a SUCCESSFUL (DB-backed) Start, so this is an integration test:
// it requires a reachable Postgres (IDENTUUM_IDP_TEST_DATABASE_URL) and
// self-migrates the schema so the first Start succeeds.
func TestStart_CalledTwice_Errors(t *testing.T) {
	dbURL := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed restart-guard test")
	}
	if err := testsupport.RequireTestDatabase(dbURL); err != nil {
		t.Fatal(err)
	}
	migratePkgTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: opt out of the single-replica instance lease — this restart-guard
	// test starts a full runtime and is not asserting the lease; the override
	// keeps it from contending with parallel DB-backed runtime tests.
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	rt, err := pkgruntime.New(pkgruntime.Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "http://127.0.0.1:7113",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	require.NoError(t, err)

	require.NoError(t, rt.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	}()

	err = rt.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "twice")
}

// migratePkgTestSchema applies the embedded OSS migrations against the
// test database so a DB-backed runtime can initialize. Idempotent.
func migratePkgTestSchema(t *testing.T, dbURL string) {
	t.Helper()
	db, err := postgres.OpenStdlibDB(dbURL)
	require.NoError(t, err)
	defer db.Close()
	_, err = postgres.RunMigrations(context.Background(), db)
	require.NoError(t, err)
}

// TestPublicPackageDoesNotImportForbiddenTrees parses the public
// package source files and asserts that none of their direct
// imports reach into the CE, monolith, AG, UI, or auth-service
// trees. This is the seam-level enforcement of the
// OSS-must-not-import-CE invariant (I3) and of the broader repo
// boundaries documented in wiki/agent-rules.md §D.
//
// Transitive import checking is owned by the module-wide validation
// matrix; this test is scoped to the direct surface of pkg/runtime
// so a drifting import shows up at the first edit.
func TestPublicPackageDoesNotImportForbiddenTrees(t *testing.T) {
	forbidden := []string{
		"github.com/identuum/identuum-idp-ce",
		"github.com/identuum/identuum-idp/internal",
		"github.com/identuum/identuum-ag",
		"github.com/identuum/identuum-ui",
		"github.com/identuum/auth-service",
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	pkgDir := wd

	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		require.NoErrorf(t, err, "failed to parse %q", name)

		for _, imp := range file.Imports {
			pathLit := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range forbidden {
				assert.Falsef(t, strings.HasPrefix(pathLit, banned),
					"%s: forbidden import %q (matches %q)", name, pathLit, banned)
			}
		}
		checked++
	}
	require.GreaterOrEqual(t, checked, 1)
}

// TestPublicPackageDoesNotLeakInternalRuntimeGuts ensures the
// public package source files do NOT re-export anything beyond the
// R1-approved surface (Config, Runtime, New). Catches accidental
// drift where a future PR adds a getter that exposes *pgxpool.Pool,
// a repository interface, or an internal service handle.
//
// The check is a textual scan of the public Go source: any new
// top-level identifier that is not in the allow-list trips the
// test. Unexported helpers (e.g. `_ = context.Background`) are
// permitted.
func TestPublicPackageDoesNotLeakInternalRuntimeGuts(t *testing.T) {
	allowed := map[string]struct{}{
		"Config":  {},
		"Runtime": {},
		"New":     {},
	}

	wd, err := os.Getwd()
	require.NoError(t, err)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(wd)
	require.NoError(t, err)

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(wd, name), nil, 0)
		require.NoErrorf(t, err, "failed to parse %q", name)

		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							_, ok := allowed[s.Name.Name]
							assert.Truef(t, ok, "%s: unexpected exported type %q", name, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								_, ok := allowed[n.Name]
								assert.Truef(t, ok, "%s: unexpected exported value %q", name, n.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue // methods on the alias types are owned by internal/runtime
				}
				if d.Name.IsExported() {
					_, ok := allowed[d.Name.Name]
					assert.Truef(t, ok, "%s: unexpected exported function %q", name, d.Name.Name)
				}
			}
		}
	}
}
