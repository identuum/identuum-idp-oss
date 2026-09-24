// Command uivendor writes the manifest of the vendored identuum-ui export
// (PLAN-E-1): `make ui-vendor` runs it after building the export from a
// clean copy of a pinned ui commit. It prints the manifest JSON on stdout —
// the ui commit, the sha256 of the ui lockfile the build installed from, the
// node and pnpm versions that built it, every file's sha256 and the tree
// digest (pkg/uiserve)— and nothing else.
//
//	go run ./tools/uivendor -dir internal/uiexport/dist -ui-commit <sha> \
//	  -lockfile <copy>/pnpm-lock.yaml -node <node --version> -pnpm <pnpm --version>
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "uivendor:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fl := flag.NewFlagSet("uivendor", flag.ContinueOnError)
	dir := fl.String("dir", "", "the vendored export directory")
	commit := fl.String("ui-commit", "", "the full ui commit SHA the export was built from")
	lockfile := fl.String("lockfile", "", "the ui lockfile the build installed from")
	node := fl.String("node", "", "the node version that built the export")
	pnpm := fl.String("pnpm", "", "the pnpm version that built the export")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *lockfile == "" || *node == "" || *pnpm == "" {
		return fmt.Errorf("-dir, -lockfile, -node and -pnpm are required")
	}
	if !fullSHA.MatchString(*commit) {
		return fmt.Errorf("-ui-commit %q is not a full lowercase commit SHA", *commit)
	}
	lock, err := os.ReadFile(*lockfile)
	if err != nil {
		return err
	}
	lockSum := sha256.Sum256(lock)
	files, err := uiserve.Files(os.DirFS(*dir))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s holds no files", *dir)
	}
	m := uiserve.Manifest{
		Schema:           uiserve.Schema,
		UICommit:         *commit,
		UILockfileSHA256: hex.EncodeToString(lockSum[:]),
		NodeVersion:      *node,
		PnpmVersion:      *pnpm,
		Files:            files,
		TreeDigest:       uiserve.TreeDigest(files),
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", out)
	return err
}
