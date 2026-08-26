// system_info_announce_test.go — STALE-BINARY-1.
//
// THE-THREE-THAT-MUST-NOT-REPEAT (2026-08-26), item 1: a dev image built
// at 13:43 served an evening of clicks against a fix that landed at
// 15:33, and nothing said so. Two teeth:
//
//  1. the RUNNING process announces its build provenance — GET
//     /system/info carries build_commit, wired to the link-time-stamped
//     internal/buildinfo.Commit;
//  2. the dev smoke REFUSES on mismatch — the Makefile's dev-smoke
//     recipe compares that announce against `git rev-parse HEAD` (with
//     the -dirty marker) and fails naming both sides, including the
//     unstamped "unknown" case.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/buildinfo"
)

// RULE: STALE-BINARY-1
func TestSystemInfo_AnnouncesBuildCommit(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/system/info", systemInfoHandler(OSSRouterDeps{Version: "test"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/system/info", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var body struct {
		BuildCommit *string `json:"build_commit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.BuildCommit == nil {
		t.Fatal("/system/info must ANNOUNCE build_commit — without it the dev smoke cannot refuse a stale binary")
	}
	if *body.BuildCommit != buildinfo.Commit {
		t.Fatalf("build_commit must be the link-time-stamped buildinfo.Commit, got %q want %q", *body.BuildCommit, buildinfo.Commit)
	}
}

// The refusal lives in make dev-smoke; this pins its comparison so the
// gate cannot be quietly deleted while the announce stays green.
func TestDevSmoke_CarriesTheStaleBinaryRefusal(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
	mk, err := os.ReadFile(filepath.Join(dir, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(mk)
	for _, want := range []string{
		`"build_commit":"`,                 // the smoke reads the announce
		"git rev-parse HEAD",               // ... and compares to the tree
		"REFUSING — STALE BINARY",          // mismatch fails by name
		"does not announce build_commit",   // an unstamped image fails too
		"--build-arg COMMIT=$(COMMIT) app", // oss-build stamps the image
	} {
		if !strings.Contains(src, want) {
			t.Errorf("Makefile lost the dev-smoke stale-binary refusal piece: %q", want)
		}
	}
}
