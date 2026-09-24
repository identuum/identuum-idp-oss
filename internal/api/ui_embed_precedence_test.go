package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/uiexport"
)

// PLAN-E-1, vendored custody: the export compiled into the binary is served
// when no UI directory is configured; the directory (IDENTUUM_IDP_UI_DIR)
// is the developer override and wins when set; neither mounts nothing.

func embeddedFixture() fstest.MapFS {
	return fstest.MapFS{
		"index.html":     {Data: []byte("<!doctype html><title>embedded</title>")},
		"assets/app.js":  {Data: []byte("console.log('embedded')")},
		"assets/app.css": {Data: []byte("body{}")},
	}
}

func TestUIPrecedence_EmbeddedIsServedWhenNoDirectoryIsSet(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{UIEmbedded: embeddedFixture()})
	for _, p := range []string{"/", "/site-admin/organizations"} {
		rec := uiGet(e, p)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>embedded</title>") {
			t.Fatalf("GET %s: %d %q, want the embedded shell", p, rec.Code, rec.Body.String())
		}
	}
	if rec := uiGet(e, "/assets/app.js"); rec.Code != http.StatusOK || rec.Body.String() != "console.log('embedded')" {
		t.Fatalf("GET /assets/app.js: %d %q, want the embedded asset", rec.Code, rec.Body.String())
	}
	// The boundary is mounted with it: /bff refuses a request without the
	// browser proof, before anything is dispatched.
	if rec := uiGet(e, "/bff/api/v1/validate"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "csrf_failed") {
		t.Fatalf("GET /bff/api/v1/validate without the proof: %d %q, want 403 csrf_failed", rec.Code, rec.Body.String())
	}
	// An unknown API path is the engine's 404, never the shell.
	if rec := uiGet(e, "/api/unknown"); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<title>") {
		t.Fatalf("GET /api/unknown: %d %q, want a plain 404", rec.Code, rec.Body.String())
	}
}

func TestUIPrecedence_TheDirectoryWinsOverTheEmbeddedExport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>override</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewOSSEngine(OSSRouterDeps{UIStaticDir: dir, UIEmbedded: embeddedFixture()})
	rec := uiGet(e, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>override</title>") {
		t.Fatalf("GET /: %d %q, want the directory's shell", rec.Code, rec.Body.String())
	}
	// Nothing of the embedded export leaks through: its asset is not the
	// directory's, so it is a 404.
	if rec := uiGet(e, "/assets/app.js"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/app.js with the override: %d, want 404", rec.Code)
	}
}

func TestUIPrecedence_NeitherMountsNothing(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	if rec := uiGet(e, "/"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET / with no UI: %d, want 404", rec.Code)
	}
	if rec := uiGet(e, "/bff/api/v1/validate"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /bff with no UI: %d, want 404 (the boundary is not mounted)", rec.Code)
	}
}

func TestUIPrecedence_AnEmbeddedExportWithoutAShellIsAFaultNotAnEmptyUI(t *testing.T) {
	report := lifecycle.NewStartupReport()
	e := NewOSSEngine(OSSRouterDeps{
		StartupReport: report,
		UIEmbedded:    fstest.MapFS{"assets/app.js": {Data: []byte("x")}},
	})
	if !report.HasFatal() {
		t.Fatal("an embedded export with no index.html must be a startup fault")
	}
	found := false
	for _, f := range report.Faults() {
		if strings.Contains(f.Reason, "the embedded UI export has no index.html") {
			found = true
		}
	}
	if !found {
		t.Fatalf("faults %v do not name the embedded export", report.Faults())
	}
	_ = e
}

// The export this binary actually embeds is served with no directory set.
func TestUIPrecedence_TheVendoredExportIsServed(t *testing.T) {
	fsys := uiexport.FS()
	if fsys == nil {
		t.Fatal("no vendored export")
	}
	e := NewOSSEngine(OSSRouterDeps{UIEmbedded: fsys})
	rec := uiGet(e, "/login")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="root">`) {
		t.Fatalf("GET /login: %d, want the vendored shell", rec.Code)
	}
}
