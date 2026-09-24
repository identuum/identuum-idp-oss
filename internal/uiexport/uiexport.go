// Package uiexport carries the identuum-ui static export this binary serves
// when no UI directory is configured (PLAN-E-1, vendored custody): the built
// files under dist/, embedded at compile time, so a plain `go build` from a
// checkout includes the UI, and manifest.json, which pins them to the ui
// commit they were built from. Both are written by `make ui-vendor` and
// checked by `make ui-vendor-check` (in `make verify`); neither is edited by
// hand. The layout does not depend on where the files came from, so a
// published ui release artifact can fill dist/ the same way.
package uiexport

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Manifest is the vendored export's integrity record (internal/uidigest).
//
//go:embed manifest.json
var Manifest []byte

// FS returns the vendored export rooted at its index.html, or nil when the
// vendored tree has no index.html (nothing to serve).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if info, err := fs.Stat(sub, "index.html"); err != nil || info.IsDir() {
		return nil
	}
	return sub
}
