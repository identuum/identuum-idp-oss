package uiserve

// The one definition of the vendored UI's integrity record (PLAN-E-1,
// vendored custody): the per-file sha256 of every file of the built
// identuum-ui export and one tree digest over them, and the manifest that
// pins them to the ui commit they were built from. `make ui-vendor` writes
// the manifest with it (tools/uivendor); `make ui-vendor-check` recomputes it
// from the files the binary embeds (internal/uiexport) and compares; the ui
// repository's publish-ui-export workflow computes the same digest.
// Deliberately free of go:embed, so the writer compiles before anything is
// vendored.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
)

// Schema names the manifest format; a reader refuses any other.
const Schema = "identuum-ui-vendor.v1"

// Manifest pins a vendored export to the ui build that produced it.
type Manifest struct {
	Schema           string            `json:"schema"`
	UICommit         string            `json:"ui_commit"`
	UILockfileSHA256 string            `json:"ui_lockfile_sha256"`
	NodeVersion      string            `json:"node_version"`
	PnpmVersion      string            `json:"pnpm_version"`
	Files            map[string]string `json:"files"`
	TreeDigest       string            `json:"tree_digest"`
}

// Files returns the sha256 (lowercase hex) of every regular file under fsys,
// keyed by its slash-separated path relative to fsys's root.
func Files(fsys fs.FS) (map[string]string, error) {
	out := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("uiserve:%s is not a regular file", p)
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		out[p] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TreeDigest is the sha256 of the lines "<sha256>  <path>\n", one per file,
// in bytewise path order — the `sha256sum` line format, so the digest can be
// reproduced outside Go from the manifest's own file list.
func TreeDigest(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b strings.Builder
	for _, p := range paths {
		b.WriteString(files[p])
		b.WriteString("  ")
		b.WriteString(p)
		b.WriteString("\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Parse reads a manifest and checks it is internally consistent: the
// schema, a non-empty file list, and a tree digest that is the digest of
// that list.
func Parse(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("uiserve:manifest: %w", err)
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("uiserve:manifest schema %q, want %q", m.Schema, Schema)
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("uiserve:manifest lists no files")
	}
	if got := TreeDigest(m.Files); got != m.TreeDigest {
		return nil, fmt.Errorf("uiserve:manifest tree_digest %s is not the digest of its own file list (%s)", m.TreeDigest, got)
	}
	return &m, nil
}

// Check recomputes every file's sha256 and the tree digest from fsys and
// compares them with the manifest. Every difference is named: a changed
// file, a file the manifest lacks, a file fsys lacks.
func Check(fsys fs.FS, m *Manifest) error {
	got, err := Files(fsys)
	if err != nil {
		return err
	}
	var diffs []string
	for p, sum := range got {
		want, ok := m.Files[p]
		switch {
		case !ok:
			diffs = append(diffs, "not in the manifest: "+p)
		case want != sum:
			diffs = append(diffs, fmt.Sprintf("changed: %s (sha256 %s, manifest %s)", p, sum, want))
		}
	}
	for p := range m.Files {
		if _, ok := got[p]; !ok {
			diffs = append(diffs, "missing from the tree: "+p)
		}
	}
	if len(diffs) > 0 {
		sort.Strings(diffs)
		return fmt.Errorf("uiserve:the vendored tree does not match its manifest:\n  %s", strings.Join(diffs, "\n  "))
	}
	if d := TreeDigest(got); d != m.TreeDigest {
		return fmt.Errorf("uiserve:tree digest %s, manifest %s", d, m.TreeDigest)
	}
	return nil
}
