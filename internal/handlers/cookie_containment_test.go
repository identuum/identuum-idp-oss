package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every net/http.SetCookie call in internal/ MUST live in auth_cookies.go.
//
// All cookie writes are funnelled through the centralized writers there
// (setAuthCookies / clearAuthCookies / writeSessionCookie /
// writeBrowserCSRFCookie), which stamp the Secure flag via
// cookieSecureForRequest. A SetCookie ANYWHERE ELSE would ship whatever Secure
// its author happened to remember — the exact BROWSER-LOGIN-PLAINHTTP-1 /
// session-cookie class of defect. Today there are six such calls (two token
// writers × set + clear, plus the two helpers), all in auth_cookies.go.
//
// This is an AST scan over CALL expressions, so a comment or string that merely
// mentions "http.SetCookie" does not trip it (a text grep would). Production
// (_test.go excluded) files only: test helpers do not ship to operators.
//
// Red-proved by planting an http.SetCookie in another internal/ file and
// watching this fire, then removing it (tree clean).
// RULE: COOKIE-WRITES-CONTAINED-1
func TestAllCookieWritesLiveInAuthCookies(t *testing.T) {
	// `go test` runs with CWD = the package directory (internal/handlers), so
	// internal/ is its parent.
	internalDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve internal/ dir: %v", err)
	}
	const ownerFile = "auth_cookies.go"

	fset := token.NewFileSet()
	var offenders []string
	ownerCalls := 0

	walkErr := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetCookie" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" {
				return true
			}
			if filepath.Base(path) == ownerFile {
				ownerCalls++
				return true
			}
			offenders = append(offenders, fset.Position(call.Pos()).String())
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scan internal/ for http.SetCookie: %v", walkErr)
	}

	// Non-vacuous: the scan must actually find the writers in auth_cookies.go,
	// or a broken scan would pass with zero offenders while missing real ones.
	if ownerCalls == 0 {
		t.Fatalf("scan found NO http.SetCookie in %s — the AST scan is broken, not the tree clean", ownerFile)
	}
	if len(offenders) > 0 {
		t.Fatalf("http.SetCookie called outside %s at %d site(s): %v — route every cookie write through the centralized writers so the Secure flag is stamped by cookieSecureForRequest", ownerFile, len(offenders), offenders)
	}
}
