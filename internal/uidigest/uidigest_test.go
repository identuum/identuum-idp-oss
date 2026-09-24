package uidigest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func tree() fstest.MapFS {
	return fstest.MapFS{
		"index.html":       {Data: []byte("<!doctype html><title>shell</title>")},
		"assets/app.js":    {Data: []byte("console.log(1)")},
		"assets/app.css":   {Data: []byte("body{}")},
		"assets/vendor.js": {Data: []byte("export{}")},
	}
}

func manifestFor(t *testing.T, fsys fstest.MapFS) *Manifest {
	t.Helper()
	files, err := Files(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return &Manifest{Schema: Schema, UICommit: strings.Repeat("a", 40), Files: files, TreeDigest: TreeDigest(files)}
}

// The tree digest is the sha256 of `sha256sum`-format lines in bytewise path
// order, so it can be recomputed outside Go from the manifest's own list.
func TestTreeDigest_IsSha256sumLinesInPathOrder(t *testing.T) {
	files := map[string]string{"b.js": sum("b"), "a/x.css": sum("x"), "A.txt": sum("A")}
	want := sum(files["A.txt"] + "  A.txt\n" + files["a/x.css"] + "  a/x.css\n" + files["b.js"] + "  b.js\n")
	if got := TreeDigest(files); got != want {
		t.Fatalf("TreeDigest = %s; want %s", got, want)
	}
}

func TestFiles_HashesEveryFileByItsPath(t *testing.T) {
	got, err := Files(tree())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got["assets/app.js"] != sum("console.log(1)") {
		t.Fatalf("Files = %v", got)
	}
}

func TestCheck_AcceptsTheTreeItWasMadeFrom(t *testing.T) {
	fsys := tree()
	if err := Check(fsys, manifestFor(t, fsys)); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// One byte changed in one vendored file is named, with both digests.
func TestCheck_OneChangedByteIsRefusedByName(t *testing.T) {
	fsys := tree()
	m := manifestFor(t, fsys)
	fsys["assets/app.js"] = &fstest.MapFile{Data: []byte("console.log(2)")}
	err := Check(fsys, m)
	if err == nil || !strings.Contains(err.Error(), "changed: assets/app.js") {
		t.Fatalf("Check after one changed byte = %v; want the file named as changed", err)
	}
}

func TestCheck_AnAddedOrAMissingFileIsRefusedByName(t *testing.T) {
	fsys := tree()
	m := manifestFor(t, fsys)
	fsys["assets/extra.js"] = &fstest.MapFile{Data: []byte("x")}
	delete(fsys, "assets/app.css")
	err := Check(fsys, m)
	if err == nil || !strings.Contains(err.Error(), "not in the manifest: assets/extra.js") ||
		!strings.Contains(err.Error(), "missing from the tree: assets/app.css") {
		t.Fatalf("Check = %v; want both files named", err)
	}
}

func TestParse_RefusesAManifestWhoseDigestIsNotItsOwnList(t *testing.T) {
	m := manifestFor(t, tree())
	raw, _ := json.Marshal(m)
	if _, err := Parse(raw); err != nil {
		t.Fatalf("Parse(consistent) = %v", err)
	}
	m.TreeDigest = strings.Repeat("0", 64)
	raw, _ = json.Marshal(m)
	if _, err := Parse(raw); err == nil || !strings.Contains(err.Error(), "not the digest of its own file list") {
		t.Fatalf("Parse(inconsistent) = %v", err)
	}
	m.Schema = "other"
	raw, _ = json.Marshal(m)
	if _, err := Parse(raw); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("Parse(wrong schema) = %v", err)
	}
}
