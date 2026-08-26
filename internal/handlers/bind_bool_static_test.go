// bind_bool_static_test.go — ABSENT-BOOL-1.
//
// THE-THREE-THAT-MUST-NOT-REPEAT (2026-08-26), item 2. `Active bool` in
// the create-organization bind struct could not tell an ABSENT field
// from an explicit false, and every UI-created organization was born
// deactivated (THE-BORN-DEACTIVATED). This check makes that shape a
// COMPILE-ADJACENT defect repo-wide: every struct that a request body is
// bound into (ShouldBindJSON / BindJSON / ShouldBindBodyWith) is parsed
// STATICALLY, and a bare `bool` field is a failure unless its
// false-means-absent collapse is DELIBERATE and recorded here with a
// justification. Pointers (*bool) are always fine — they distinguish.
//
// The allowlist is a ratchet: an entry must name a real, current hit
// (stale entries fail) and carry a non-empty justification.
package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// bindBoolJustified records every DELIBERATE bare-bool bind field.
// Key: "<repo-relative-file>:<funcOrType>.<Field>".
var bindBoolJustified = map[string]string{
	"internal/handlers/auth_sessions.go:localLoginRequest.RememberMe":                       "login-shaped opt-in: absent and false both mean a standard-lifetime session; remember-me extends lifetime only on an explicit true. Absence collapsing to the shorter session is the safe direction.",
	"internal/handlers/clients.go:HandleCreateClient.req.IsPublic":                          "create-shaped: absent and false both mean a CONFIDENTIAL client — the stronger posture; public (no-secret) clients are an explicit opt-in. Absence collapsing to the safe default is deliberate.",
	"internal/handlers/clients.go:HandleCreateClient.req.BackchannelLogoutSessionRequired":  "OIDC Back-Channel Logout 1.0 §2: backchannel_logout_session_required 'If omitted, the default value is false' — absent-means-false IS the spec.",
	"internal/handlers/clients.go:HandleCreateClient.req.FrontchannelLogoutSessionRequired": "OIDC Front-Channel Logout 1.0 §2: frontchannel_logout_session_required defaults to false when omitted — absent-means-false IS the spec.",
	"internal/handlers/dcr.go:dcrRequest.BackchannelLogoutSessionRequired":                  "RFC 7591 DCR metadata: omitted members take their default values; OIDC Back-Channel Logout defines that default as false.",
	"internal/handlers/dcr.go:dcrRequest.FrontchannelLogoutSessionRequired":                 "RFC 7591 DCR metadata: omitted members take their default values; OIDC Front-Channel Logout defines that default as false.",
}

// findOSSRoot walks up from the test's wd to the module root.
func findOSSRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// RULE: ABSENT-BOOL-1
func TestBindStructs_NoBareBoolFields(t *testing.T) {
	root := findOSSRoot(t)

	type hit struct{ key, detail string }
	var hits []hit

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "node_modules" || base == ".git" || base == ".gograph" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel, _ := filepath.Rel(root, path)

		// Named struct types in this file, for bind targets declared as
		// named types rather than inline literals.
		named := map[string]*ast.StructType{}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if st, ok := ts.Type.(*ast.StructType); ok {
					named[ts.Name.Name] = st
				}
			}
		}

		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Local var name -> struct type (inline literal or named).
			local := map[string]*ast.StructType{}
			localLabel := map[string]string{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if ds, ok := n.(*ast.DeclStmt); ok {
					if gd, ok := ds.Decl.(*ast.GenDecl); ok {
						for _, spec := range gd.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							var st *ast.StructType
							label := ""
							switch typ := vs.Type.(type) {
							case *ast.StructType:
								st = typ
							case *ast.Ident:
								st = named[typ.Name]
								label = typ.Name
							}
							if st != nil {
								for _, name := range vs.Names {
									local[name.Name] = st
									if label == "" {
										localLabel[name.Name] = fn.Name.Name + "." + name.Name
									} else {
										localLabel[name.Name] = label
									}
								}
							}
						}
					}
				}
				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "ShouldBindJSON", "BindJSON", "ShouldBindBodyWith":
				default:
					return true
				}
				for _, arg := range call.Args {
					un, ok := arg.(*ast.UnaryExpr)
					if !ok || un.Op != token.AND {
						continue
					}
					id, ok := un.X.(*ast.Ident)
					if !ok {
						continue
					}
					st := local[id.Name]
					if st == nil {
						continue // bound into a non-local or unresolved target — out of this checker's static reach
					}
					label := localLabel[id.Name]
					if label == "" {
						label = fn.Name.Name + "." + id.Name
					}
					for _, field := range st.Fields.List {
						ft, ok := field.Type.(*ast.Ident)
						if !ok || ft.Name != "bool" {
							continue
						}
						for _, fname := range field.Names {
							key := rel + ":" + label + "." + fname.Name
							hits = append(hits, hit{key: key,
								detail: fmt.Sprintf("%s bound at %s", key, fset.Position(call.Pos()))})
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	var fails []string
	for _, h := range hits {
		seen[h.key] = true
		just, ok := bindBoolJustified[h.key]
		if !ok {
			fails = append(fails, "BARE BOOL in a bind struct (absent and false are indistinguishable): "+h.detail+
				" — use *bool, or record a deliberate justification in bindBoolJustified")
			continue
		}
		if strings.TrimSpace(just) == "" {
			fails = append(fails, "EMPTY justification for "+h.key)
		}
	}
	for key := range bindBoolJustified {
		if !seen[key] {
			fails = append(fails, "STALE allowlist entry (no such bind field anymore): "+key)
		}
	}
	sort.Strings(fails)
	for _, f := range fails {
		t.Error(f)
	}
}
