package domain

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestAuditEventTypeCatalog_MatchesRecordedNames: the catalog the console's
// event-type filter is built from (AllAuditEventTypeGroups) lists exactly
// the event_type values this server can write. The audit row's event_type is
// audit.Event.Action (service/audit_persistent.go), so the test reads every
// non-test Go file of the module and collects each Action value:
//   - a string literal, or a string constant (also through string(X));
//   - a function or closure parameter: the string literals passed at that
//     parameter position by every call of that function name ("" is skipped:
//     startBrowserSession records nothing for it).
//
// A value it cannot resolve fails the test with its position, so a new
// computed Action cannot slip past the catalog.
// At 3e1fa09 the catalog is the pre-split underscore list: it misses most
// recorded dot names and lists names nothing records.
//
// The catalog half of the rule: exactly the recorded names.
//
// RULE: AUDIT-EVENT-CATALOG-1
func TestAuditEventTypeCatalog_MatchesRecordedNames(t *testing.T) {
	recorded, unresolved := collectRecordedAuditActions(t, filepath.Join("..", ".."))
	for _, u := range unresolved {
		t.Errorf("audit Action not resolvable to a fixed name: %s (use a literal or a constant, or pass literals)", u)
	}
	if len(recorded) < 30 {
		t.Fatalf("control: only %d recorded names found; the source walk is broken", len(recorded))
	}

	catalog := map[string]bool{}
	for _, g := range AllAuditEventTypeGroups {
		for _, et := range g.Types {
			catalog[string(et)] = true
		}
	}
	var missing, extra []string
	for name := range recorded {
		if !catalog[name] {
			missing = append(missing, name)
		}
	}
	for name := range catalog {
		if !recorded[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%d recorded event types are not in the catalog (the filter cannot offer them): %s", len(missing), strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("%d catalog entries are never recorded (the filter offers a type with no rows): %s", len(extra), strings.Join(extra, ", "))
	}
	t.Logf("recorded=%d catalog=%d missing=%d extra=%d", len(recorded), len(catalog), len(missing), len(extra))
	if os.Getenv("AUDIT_DRIFT_DUMP") != "" {
		names := make([]string, 0, len(recorded))
		for n := range recorded {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Logf("recorded names: %s", strings.Join(names, " "))
	}
}

type actionParam struct {
	dir   string // package directory: calls are matched inside it only
	fn    string // function, method or closure variable name
	index int    // parameter position
}

func collectRecordedAuditActions(t *testing.T, root string) (map[string]bool, []string) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".gograph", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// String constants by bare name (package-qualified uses are matched by
	// their selector's name; the names are unique enough for this module,
	// and a collision with two values fails below).
	consts := map[string]string{}
	clash := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						v, _ := strconv.Unquote(bl.Value)
						if old, seen := consts[n.Name]; seen && old != v {
							clash[n.Name] = true
						}
						consts[n.Name] = v
					}
				}
			}
		}
	}

	recorded := map[string]bool{}
	var unresolved []string
	params := map[actionParam]string{} // param -> position of the Action use

	resolve := func(e ast.Expr) (string, bool) {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				v, err := strconv.Unquote(x.Value)
				return v, err == nil
			}
		case *ast.Ident:
			if v, ok := consts[x.Name]; ok && !clash[x.Name] {
				return v, true
			}
		case *ast.SelectorExpr:
			if v, ok := consts[x.Sel.Name]; ok && !clash[x.Sel.Name] {
				return v, true
			}
		case *ast.CallExpr: // string(domain.AuditX)
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "string" && len(x.Args) == 1 {
				if sel, ok := x.Args[0].(*ast.SelectorExpr); ok {
					if v, ok := consts[sel.Sel.Name]; ok && !clash[sel.Sel.Name] {
						return v, true
					}
				}
				if id2, ok := x.Args[0].(*ast.Ident); ok {
					if v, ok := consts[id2.Name]; ok && !clash[id2.Name] {
						return v, true
					}
				}
			}
		}
		return "", false
	}

	isAuditEvent := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && id.Name == "audit" && x.Sel.Name == "Event"
		case *ast.Ident:
			return x.Name == "Event" // inside package audit
		}
		return false
	}

	for _, f := range files {
		// Parameter names of every enclosing function / closure, by name.
		type frame struct {
			name   string
			params []string
			locals map[string][]ast.Expr // action := "x"; action = "y"
		}
		var stack []frame
		localsOf := func(body *ast.BlockStmt) map[string][]ast.Expr {
			out := map[string][]ast.Expr{}
			if body == nil {
				return out
			}
			ast.Inspect(body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
					for i, l := range as.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							out[id.Name] = append(out[id.Name], as.Rhs[i])
						}
					}
				}
				return true
			})
			return out
		}
		var visit func(n ast.Node) bool
		paramsOf := func(ft *ast.FuncType) []string {
			var out []string
			if ft.Params == nil {
				return out
			}
			for _, fld := range ft.Params.List {
				if len(fld.Names) == 0 {
					out = append(out, "_")
				}
				for _, nm := range fld.Names {
					out = append(out, nm.Name)
				}
			}
			return out
		}
		handleValue := func(v ast.Expr) {
			if s, ok := resolve(v); ok {
				if s != "" {
					recorded[s] = true
				}
				return
			}
			pos := fset.Position(v.Pos()).String()
			if id, ok := v.(*ast.Ident); ok {
				for i := len(stack) - 1; i >= 0; i-- {
					if rhs, ok := stack[i].locals[id.Name]; ok {
						all := true
						for _, r := range rhs {
							if s, ok := resolve(r); ok {
								if s != "" {
									recorded[s] = true
								}
							} else {
								all = false
							}
						}
						if all {
							return
						}
						unresolved = append(unresolved, pos+" (local "+id.Name+")")
						return
					}
					for pi, pn := range stack[i].params {
						if pn == id.Name && stack[i].name != "" {
							params[actionParam{filepath.Dir(fset.Position(v.Pos()).Filename), stack[i].name, pi}] = pos
							return
						}
					}
				}
			}
			unresolved = append(unresolved, pos)
		}
		visit = func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				stack = append(stack, frame{x.Name.Name, paramsOf(x.Type), localsOf(x.Body)})
				if x.Body != nil {
					ast.Inspect(x.Body, visit)
				}
				stack = stack[:len(stack)-1]
				return false
			case *ast.AssignStmt:
				// record := func(action string) { ... }
				if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
					if fl, ok := x.Rhs[0].(*ast.FuncLit); ok {
						name := ""
						if id, ok := x.Lhs[0].(*ast.Ident); ok {
							name = id.Name
						}
						stack = append(stack, frame{name, paramsOf(fl.Type), localsOf(fl.Body)})
						ast.Inspect(fl.Body, visit)
						stack = stack[:len(stack)-1]
						return false
					}
				}
				// ev.Action = "..."
				for i, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Action" && i < len(x.Rhs) {
						handleValue(x.Rhs[i])
					}
				}
			case *ast.CompositeLit:
				if isAuditEvent(x.Type) {
					for _, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Action" {
								handleValue(kv.Value)
							}
						}
					}
				}
			}
			return true
		}
		ast.Inspect(f, visit)
	}

	// Literal arguments at each Action-carrying parameter, by callee name.
	for _, f := range files {
		dir := filepath.Dir(fset.Position(f.Pos()).Filename)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			for ap := range params {
				if ap.dir != dir || ap.fn != name || ap.index >= len(call.Args) {
					continue
				}
				if s, ok := resolve(call.Args[ap.index]); ok {
					if s != "" {
						recorded[s] = true
					}
				} else {
					unresolved = append(unresolved, fset.Position(call.Args[ap.index].Pos()).String()+" (argument to "+name+")")
				}
			}
			return true
		})
	}
	return recorded, unresolved
}
