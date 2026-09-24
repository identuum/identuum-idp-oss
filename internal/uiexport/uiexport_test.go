package uiexport

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

// The bytes this binary embeds are exactly the export its manifest records:
// every file's sha256 and the tree digest recomputed from the embedded files
// (`make ui-vendor-check`, in `make verify`).
func TestVendoredTreeMatchesManifest(t *testing.T) {
	m, err := uiserve.Parse(Manifest)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	fsys := FS()
	if fsys == nil {
		t.Fatal("the vendored export has no index.html")
	}
	if err := uiserve.Check(fsys, m); err != nil {
		t.Fatal(err)
	}
}
