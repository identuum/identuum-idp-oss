// Command clockfuse detects the CLOCK-FUSE signature.
//
// THE SIGNATURE, from identuum-idp-ce@433bc6c: a test builds a fixture from a
// FROZEN clock (a hardcoded time.Date), then hands it to code that reads the
// WALL clock, because the construction site omitted the `now func() time.Time`
// field its own struct already offers. The test passes for as long as the
// fixture's offset lasts and then fails on a date nobody chose. In that case it
// was green for 45 days and red for 3 hours before anyone noticed, and no file
// had changed — so mtime, git log and code review all see nothing.
//
// What this reports is the PRECONDITION, not the verdict: a composite literal
// of a seam-bearing struct that leaves `now` unset. Some of those are benign
// (no frozen fixture is involved, or the wall clock is the point). Triage is a
// human step; the detector's job is to make the candidate set finite and
// stable rather than to guess.
//
// A THIRD shape exists and is checked separately: a clock passed POSITIONALLY
// to a New*/new* constructor, e.g.
//
//	newUserinfoHandler(tokens, users, func() time.Time { return now })
//
// There is no field to omit, so shapes 1 and 2 are blind to it in both
// directions. What is reportable there is a MISMATCH: a test function that
// freezes a clock with time.Date AND hands a constructor the WALL clock at the
// same time. That is the fuse in miniature — one half frozen, one half not.
//
// Two passes, stdlib only:
//  1. every non-test .go file, for struct types declaring `now func() time.Time`
//  2. every _test.go file, for composite literals of those types omitting `now`
//
// Matching is by type NAME within the module. A same-package literal appears as
// `configType{...}` and a cross-package one as `pkg.ConfigType{...}`; both are
// matched on the identifier, which over-approximates rather than under-
// approximates. For a detector whose failure mode is a silent miss, that is the
// correct direction to err.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// TWO SHAPES, because matching only the first one produced a FALSE NEGATIVE.
//
//	unexported `now` — the struct is built directly in tests. This is the
//	    identuum-idp-ce shape, and it is what 433bc6c was.
//	exported `Now`   — the seam lives on an options/deps struct handed to a
//	    New* constructor. This is the identuum-idp-oss shape, and the first
//	    version of this tool could not see it: it reported CLEAN there while
//	    measuring nothing, because internal/service exposes 52 New*
//	    constructors and not one takes a clock — token_service.go sets
//	    `now: time.Now` INSIDE the constructor, unreachable from any test.
//
// A detector that reports CLEAN for a shape it cannot express is worse than no
// detector, so both names are matched and the finding says which.
// seamFields are the field names a clock seam is allowed to have.
//
// `clock` IS ON THIS LIST BECAUSE OMITTING IT HID A REAL SEAM. identuum-idp-oss's
// DCRInitialAccessTokenService declares `clock func() time.Time` and reads it as
// `s.clock()`; the detector had no name for that, so the seam did not exist as
// far as every census this fleet has run. It was found by tracing a
// `!at.Before(<stored expiry>)` site that no seam appeared to feed. Measured
// across all four repos: it is the ONLY struct field of type func() time.Time
// outside this list.
var seamFields = []string{"now", "Now", "clock", "Clock"}

// isClockFunc reports whether expr is exactly `func() time.Time`.
func isClockFunc(expr ast.Expr) bool {
	ft, ok := expr.(*ast.FuncType)
	if !ok || ft.Params == nil || len(ft.Params.List) != 0 {
		return false
	}
	if ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	sel, ok := ft.Results.List[0].Type.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Time" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "time"
}

func walkGo(root string, fn func(path string) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", ".gograph":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		return fn(path)
	})
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	fset := token.NewFileSet()

	// Pass 1 — types that OFFER the seam.
	// KEYED BY DIRECTORY, NOT BY BARE TYPE NAME (NAME-COLLIDES-AND-PLUMBING-COUNTS,
	// 2026-08-02). A flat name->field map collapses every same-named struct in the
	// module into one entry: identuum-ag-oss declares SEVEN seam-bearing structs
	// under TWO names (Service x6), so ONE injection into ONE Service cleared all
	// six. identuum-idp-ce: 50 structs, 42 names (Options x5, Service x5); ag-ce: 7
	// structs, 4 names. Directory is the package boundary funcResult and
	// methodResult already use, so this makes the whole tool agree with itself.
	seam := map[string]map[string]string{} // dir -> type name -> seam field
	// A QUALIFIED TYPE RESOLVES THROUGH THE FILE'S OWN IMPORT BLOCK, never through
	// a package NAME (ONE-BLOCKER, 2026-08-02). The previous version mapped package
	// name -> directories and took the FIRST match. identuum-idp-oss alone has SIX
	// package names living in two directories each, so that lookup was ambiguous —
	// and an ambiguous key in a gate is a gate that CAN BE SILENCED BY ADDING A
	// FILE: declare `package mw` in a new directory and a finding can start
	// resolving somewhere it does not belong. The import block is unambiguous: it
	// says exactly which path this file means.
	modPath := modulePath(root)
	fileImports := map[string]map[string]string{} // file -> local name -> import path
	err := walkGo(root, func(path string) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // unparseable file is not this tool's business
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, nm := range fld.Names {
					if !isClockFunc(fld.Type) {
						continue
					}
					for _, want := range seamFields {
						if nm.Name == want {
							d := filepath.Dir(path)
							if seam[d] == nil {
								seam[d] = map[string]string{}
							}
							seam[d][ts.Name.Name] = want
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "clockfuse:", err)
		os.Exit(2)
	}

	seamCount := 0
	for _, m := range seam {
		seamCount += len(m)
	}
	if seamCount == 0 {
		fmt.Println("clockfuse: no struct in this module declares a `now`/`Now func() time.Time` seam; nothing to check.")
		return
	}

	// Pass 2 — test-file literals of those types that OMIT the seam.
	type finding struct {
		pos, typ, field string
	}
	var found []finding
	err = walkGo(root, func(path string) error {
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}
			var name string
			switch t := cl.Type.(type) {
			case *ast.Ident:
				name = t.Name
			case *ast.SelectorExpr:
				if t.Sel != nil {
					name = t.Sel.Name
				}
			}
			if name == "" {
				return true
			}
			field, isSeam := seam[filepath.Dir(path)][name]
			if !isSeam {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
					return true // seam supplied
				}
			}
			found = append(found, finding{
				pos:   fmt.Sprintf("%s:%d", path, fset.Position(cl.Pos()).Line),
				typ:   name,
				field: field,
			})
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "clockfuse:", err)
		os.Exit(2)
	}

	// Pass 3 — POSITIONAL clock arguments (shape 3).
	//
	// Collect constructors that take a func() time.Time positionally, then look
	// for test funcs that freeze a clock and yet hand one of them the wall
	// clock. A test doing both is mixing two clocks in one scope, which is the
	// 433bc6c failure written a different way.
	ctor := map[string]int{} // constructor name -> index of its clock parameter
	_ = walkGo(root, func(path string) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Type.Params == nil {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(fd.Name.Name), "new") {
				continue
			}
			idx := 0
			for _, p := range fd.Type.Params.List {
				n := len(p.Names)
				if n == 0 {
					n = 1
				}
				if isClockFunc(p.Type) {
					ctor[fd.Name.Name] = idx
				}
				idx += n
			}
		}
		return nil
	})

	isWallClock := func(e ast.Expr) bool {
		if sel, ok := e.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" && sel.Sel.Name == "Now" {
				return true
			}
		}
		if fl, ok := e.(*ast.FuncLit); ok && fl.Body != nil {
			wall := false
			ast.Inspect(fl.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" && sel.Sel.Name == "Now" {
						wall = true
					}
				}
				return true
			})
			return wall
		}
		return false
	}

	var mixed []finding
	if len(ctor) > 0 {
		_ = walkGo(root, func(path string) error {
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return nil
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				frozen := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" && sel.Sel.Name == "Date" {
							frozen = true
						}
					}
					return true
				})
				if !frozen {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					id, ok := call.Fun.(*ast.Ident)
					if !ok {
						return true
					}
					pos, isCtor := ctor[id.Name]
					if !isCtor || pos >= len(call.Args) {
						return true
					}
					if isWallClock(call.Args[pos]) {
						mixed = append(mixed, finding{
							pos:   fmt.Sprintf("%s:%d", path, fset.Position(call.Pos()).Line),
							typ:   id.Name,
							field: "positional clock arg",
						})
					}
					return true
				})
			}
			return nil
		})
	}

	// Pass 4 — FUNCTIONAL-OPTION clock seams (shape 4).
	//
	// identuum-ag-oss injects every clock seam through an option:
	//
	//	func WithClock(fn func() time.Time) ServiceOption {
	//		return func(s *Service) { s.now = fn }
	//	}
	//
	// and its tests never build a Service{...} literal at all, so pass 2 has
	// nothing to match and reports CLEAN while its construction sites go
	// unexamined. A CLEAN that measures the absence of a CONSTRUCT rather than
	// the absence of a fuse is worse than no answer, because it is believed.
	//
	// Keyed on the option's TYPE and its assignment target, never on parameter
	// name: five of the six ag-oss options name it `now` and the sixth names it
	// `fn`, so a name-keyed pass would silently miss revocation.
	//
	// KEYED PER DIRECTORY, unlike passes 1-2, and that difference is load-
	// bearing. Those passes match TYPE names, where collapsing `Service` across
	// packages merely over-approximates — the safe direction. Here the map runs
	// constructor -> type, and 12 packages in ag-oss declare `NewService`; one
	// of them (compensationlog) returns `Emitter`, so a name-keyed map lets the
	// last package walked overwrite the other eleven and the pass silently
	// matches nothing at all. Per-directory keying is what makes it fire. The
	// cost is that a constructor called from another package's tests is not
	// resolved; that is the conservative direction, and these are tested
	// in-package.
	optOf := map[string]map[string]string{}  // dir -> option func -> type
	ctorOf := map[string]map[string]string{} // dir -> constructor -> type
	_ = walkGo(root, func(path string) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(path)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			if strings.HasPrefix(fd.Name.Name, "With") && len(fd.Type.Params.List) == 1 &&
				isClockFunc(fd.Type.Params.List[0].Type) {
				if tn := optionTarget(fd); tn != "" {
					if optOf[dir] == nil {
						optOf[dir] = map[string]string{}
					}
					optOf[dir][fd.Name.Name] = tn
				}
				continue
			}
			if !strings.HasPrefix(strings.ToLower(fd.Name.Name), "new") ||
				fd.Type.Results == nil || len(fd.Type.Results.List) == 0 {
				continue
			}
			if tn := baseTypeName(fd.Type.Results.List[0].Type); tn != "" {
				if ctorOf[dir] == nil {
					ctorOf[dir] = map[string]string{}
				}
				ctorOf[dir][fd.Name.Name] = tn
			}
		}
		return nil
	})

	var optless []finding
	_ = walkGo(root, func(path string) error {
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		ctors, opts := ctorOf[dir], optOf[dir]
		if len(ctors) == 0 || len(opts) == 0 {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !freezesClock(fd.Body) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				typ, ok := ctors[calleeName(call.Fun)]
				if !ok {
					return true
				}
				// Only a type some option in this package configures can be
				// judged; anything else has no seam to omit.
				configured := false
				for _, ot := range opts {
					if ot == typ {
						configured = true
					}
				}
				if !configured {
					return true
				}
				for _, a := range call.Args {
					inner, ok := a.(*ast.CallExpr)
					if !ok {
						continue
					}
					if opts[calleeName(inner.Fun)] == typ {
						return true // seam supplied through its option
					}
				}
				optless = append(optless, finding{
					pos:   fmt.Sprintf("%s:%d", path, fset.Position(call.Pos()).Line),
					typ:   calleeName(call.Fun),
					field: typ,
				})
				return true
			})
		}
		return nil
	})

	// Pass 3 — CENSUS: how often is each seam actually INJECTED, and with what?
	//
	// THE BLIND SPOT THIS CLOSES (CLOCK-SEAM-UNUSED, 2026-08-02). Passes 1 and 2
	// answer "which literals OMIT the seam". They cannot distinguish a seam that
	// NOTHING EVER CONSTRUCTS from a seam that EVERY construction supplies
	// correctly: both produce no omission findings, so both print nothing. Four
	// exported `Now func() time.Time` fields in identuum-idp-oss were declared,
	// defaulted to time.Now, and injected by nobody — a seam that exists only in
	// the type, which is indistinguishable from a seam that works.
	//
	// A WALL-CLOCK INJECTION IS NOT AN INJECTION FOR THIS PURPOSE. `Now: time.Now`
	// supplies the field and changes nothing; the seam's whole value is the ability
	// to hand it a clock that does not move. The census therefore counts wall-clock
	// and non-wall-clock assignments SEPARATELY, and it is the second number that
	// says whether the seam has ever done its job.
	//
	// Production files are scanned too: an injection from production code counts.
	//
	// IT REUSES THE isWallClock CLOSURE ABOVE RATHER THAN A NEW ONE. I wrote a
	// second, narrower version — body must be exactly `return time.Now()` — and
	// staticcheck caught it as unused because the closure shadows it. The existing
	// one is also the CORRECT one here: it treats any func literal MENTIONING
	// time.Now as the wall clock, and `func() time.Time { return time.Now().Add(-h) }`
	// is exactly that — a clock that still moves, and so cannot hold a boundary
	// still. The narrower rule would have counted it as a real injection.
	type seamKey struct{ dir, typ, field string }

	// PASS 1b — THE OPTIONS→FIELD EDGE (CREDIT-THE-SEAM, 2026-08-02).
	//
	// An options seam and the field it feeds are ONE unit. `par.AuthCodeOptions.Now`
	// read TEST 10 while `par.AuthCodeService.now` read TEST 0, because every test
	// injects through the constructor's options parameter — which is the only seam
	// those constructors accept. The boundary was pinned and the census said the
	// service had never been frozen.
	//
	// THE EDGE IS READ, NOT HARDCODED. A constructor qualifies when all three hold:
	//   1. it RETURNS a type T that declares a seam field f;
	//   2. it TAKES a parameter of type O that declares a seam field g;
	//   3. its body READS `<param>.g` AND writes f on the constructed value —
	//      either as a keyed element of a T composite literal or as `x.f = ...`.
	// The `if now == nil { now = time.Now }` idiom sits between the read and the
	// write and needs no special case: both endpoints are still present.
	//
	// An injection into (O,g) then CREDITS (T,f). TEST vs PRODUCTION stays decided
	// by the CALLER's file — the constructor body is production plumbing either way.
	// Keyed by seamKey rather than a twin struct: staticcheck flagged the
	// duplicate (S1016), and one type for "which seam" is also simply correct.
	credit := map[seamKey]seamKey{} // options seam -> field seam it feeds
	err = walkGo(root, func(path string) error {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(path)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || fd.Type == nil {
				continue
			}
			if fd.Type.Results == nil {
				continue
			}
			// ANY result may be the constructed type, not just a sole one:
			// `func NewValidator(cfg Config) (*Validator, error)` returns two, and
			// requiring exactly one silently skipped every constructor in
			// identuum-ag-ce — the edge fired nowhere there and the count did not move.
			retType, retField := "", ""
			for _, res := range fd.Type.Results.List {
				rt := baseTypeName(res.Type)
				if rf, ok := seam[dir][rt]; ok {
					retType, retField = rt, rf
					break
				}
			}
			if retType == "" {
				continue
			}
			if fd.Type.Params == nil {
				continue
			}
			for _, param := range fd.Type.Params.List {
				optType := baseTypeName(param.Type)
				optField, ok := seam[dir][optType]
				if !ok {
					continue
				}
				for _, nm := range param.Names {
					if !readsSelector(fd.Body, nm.Name, optField) {
						continue
					}
					if !writesField(fd.Body, retType, retField) {
						continue
					}
					credit[seamKey{dir, optType, optField}] = seamKey{dir, retType, retField}
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "clockfuse: %v\n", err)
		os.Exit(2)
	}

	// PRE-PASS for attribution — declared RESULT types, read off FuncDecls.
	//
	// WHY (ATTRIBUTE-AND-SAY, 2026-08-02): three assignments were unattributable and
	// therefore suppressed the verdict for every seam sharing the field name `now` —
	// roughly thirty types made undecidable by three sites. Both shapes are ordinary
	// test code and both are answerable from the AST alone, so no go/types:
	//
	//	svc := newCSRFHarness(t)                       // func -> declared result
	//	svc := newBackchannelHarness(t).WithFoo(x)     // method chain -> declared result
	//
	// Keyed per DIRECTORY, because that is the package boundary this tool already
	// uses everywhere else.
	funcResult := map[string]map[string]string{}   // dir -> func name -> result type
	methodResult := map[string]map[string]string{} // dir -> "Recv.Method" -> result type
	// fieldType records EVERY struct field's type name, so a receiver held in a
	// fixture struct — `svc := h.svc; svc.now = ...` — can be attributed. Without
	// it one such assignment goes unattributable and shadows every seam sharing
	// that field name in its package (TWENTY-DEADLINES, 2026-08-02).
	fieldType := map[string]map[string]string{}       // dir -> "Type.Field" -> field type
	declaredTypes := map[string]bool{}                // declared struct names, MODULE-WIDE
	funcDecl := map[string]map[string]*ast.FuncDecl{} // dir -> func name -> decl (for option bodies)
	methodsOf := map[string][]*ast.FuncDecl{}         // "dir.Type" -> its production methods
	callables := map[string][]*ast.FuncDecl{}         // BARE function/method name -> every decl with that name, MODULE-WIDE
	err = walkGo(root, func(path string) error {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(path)
		if funcResult[dir] == nil {
			funcResult[dir] = map[string]string{}
			methodResult[dir] = map[string]string{}
			funcDecl[dir] = map[string]*ast.FuncDecl{}
		}
		// Import blocks, from EVERY file — pass 1 skips _test.go, and a
		// cross-package injection written from a TEST is exactly the case this
		// resolution exists for. Collecting them in pass 1 left every test file with
		// an empty import map, so three seams silently stopped being credited.
		imports := map[string]string{}
		for _, spec := range f.Imports {
			ip, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			local := ip[strings.LastIndex(ip, "/")+1:]
			if spec.Name != nil {
				local = spec.Name.Name
			}
			imports[local] = ip
		}
		fileImports[path] = imports

		// Methods per receiver type, for the D/S classification below. PRODUCTION
		// files only: DEADLINE is a property of what the SHIPPED receiver does with
		// the clock, and a test helper method that happens to read the seam would
		// otherwise promote a stamp into a deadline.
		if !strings.HasSuffix(path, "_test.go") {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
					continue
				}
				if rt := baseTypeName(fd.Recv.List[0].Type); rt != "" {
					methodsOf[dir+"."+rt] = append(methodsOf[dir+"."+rt], fd)
				}
			}
			// Callables for the interprocedural follow in classifySeam, keyed by the
			// BARE function or method name and pooled MODULE-WIDE — not "dir.Name", and
			// not by receiver type, because the receiver's type is exactly what the AST
			// cannot give us at the call site. What keeps a bare, module-wide key honest
			// is the parameter TYPE guard in paramCmpSites: a candidate is followed only
			// when its k-th parameter is really a time.Time or time.Duration.
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Body == nil {
					continue
				}
				callables[fd.Name.Name] = append(callables[fd.Name.Name], fd)
			}
		}

		// Struct field types, from EVERY file — pass 1 skips _test.go, and a test
		// fixture struct is exactly where a receiver like `h.svc` lives.
		if fieldType[dir] == nil {
			fieldType[dir] = map[string]string{}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			// MODULE-WIDE, not per directory: `org.NewClaimStore(...)` is called from
			// cmd/identuum-idp, and the type it builds is declared in
			// internal/commercial/org. Scoping this to the CALLER's package silently
			// un-credited that seam and reported it as a never-injected DEADLINE.
			declaredTypes[ts.Name.Name] = true
			for _, fld := range st.Fields.List {
				for _, nm := range fld.Names {
					if ft := baseTypeName(fld.Type); ft != "" {
						fieldType[dir][ts.Name.Name+"."+nm.Name] = ft
					}
				}
			}
			return true
		})
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Type == nil || fd.Type.Results == nil {
				continue
			}
			if len(fd.Type.Results.List) != 1 {
				continue // a multi-result helper is not a constructor shape
			}
			res := baseTypeName(fd.Type.Results.List[0].Type)
			if fd.Recv == nil {
				// THE DECL IS STORED EVEN WHEN ITS RESULT HAS NO NAMEABLE BASE TYPE.
				// `func fixedClock(t time.Time) func() time.Time` returns a FuncType, so
				// baseTypeName is "" — and an earlier `continue` on that emptiness kept
				// the decl out of the map entirely, which made `WithClock(fixedClock(now))`
				// unresolvable and left internal/auth/sessionstore's six frozen tests
				// reading as zero. The empty-name guard belongs to funcResult alone.
				funcDecl[dir][fd.Name.Name] = fd
				if res != "" {
					funcResult[dir][fd.Name.Name] = res
				}
				continue
			}
			if res == "" {
				continue
			}
			if len(fd.Recv.List) == 1 {
				if recv := baseTypeName(fd.Recv.List[0].Type); recv != "" {
					methodResult[dir][recv+"."+fd.Name.Name] = res
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "clockfuse: %v\n", err)
		os.Exit(2)
	}

	// THREE INJECTION SHAPES, NOT ONE (AG-MEASURE-FIRST, 2026-08-02). The first
	// version of this census inspected ONLY *ast.CompositeLit / *ast.KeyValueExpr,
	// which is one shape of three — and in identuum-idp-oss it is the RAREST. Of 43
	// `func() time.Time` literals in _test.go, exactly ONE sits on a `now:`/`Now:`
	// key; 40 are ASSIGNMENTS (`svc.now = ...`) and the rest are option calls
	// (`jwt.WithTimeFunc`). So "27 seams have never been injected" was FALSE for
	// every seam frozen by assignment, which is nearly all of them.
	//
	// ASSIGNMENTS ARE ATTRIBUTED BY LOCAL TYPE RESOLUTION, and where that fails the
	// census SAYS SO rather than guessing. `svc := NewFooService(...)` or
	// `svc := &FooService{...}` in the same function resolves `svc.now = ...` to
	// FooService.now. A receiver whose type cannot be resolved from the AST alone
	// goes to an UNATTRIBUTED bucket keyed by field name, and any seam sharing that
	// field name is then NOT declared never-injected — the verdict stays
	// conservative instead of confidently wrong.
	// TEST AND PRODUCTION ARE COUNTED SEPARATELY. Only a test injection can clear a
	// seam; production writes are the plumbing that makes the seam settable at all.
	wallTest := map[seamKey]int{}
	wallProd := map[seamKey]int{}
	frozenTest := map[seamKey]int{}
	frozenProd := map[seamKey]int{}
	frozenWhere := map[seamKey][]string{}
	// WHICH SHAPE CLEARED IT (OPTION-CALL-IS-THE-INJECTION, 2026-08-02): a census
	// that says a seam is exercised without saying HOW cannot be checked against the
	// code by a reader, and three of the last four defects were shapes the tool
	// could not see. literal / assignment / option, per seam.
	shapeTest := map[seamKey]map[string]int{}
	// Keyed "dir.field": an unattributable assignment can only shadow seams in its
	// OWN package now that the seam map is per-directory.
	unattributedTest := map[string]int{}
	unattributedProd := map[string]int{}
	unattributedWhere := map[string][]string{}
	optionInject := map[string]int{} // option/positional callee -> non-wall injections
	err = walkGo(root, func(path string) error {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		isTest := strings.HasSuffix(path, "_test.go")
		// recordIn takes the OWNING directory, so a cross-package injection is
		// credited where the seam is declared rather than where the test sits.
		var recordIn func(seamDir, name, field string, val ast.Expr, pos token.Pos, shape string)
		recordIn = func(seamDir, name, field string, val ast.Expr, pos token.Pos, shape string) {
			k := seamKey{seamDir, name, field}
			wall := isWallClock(val)
			switch {
			case wall && isTest:
				wallTest[k]++
			case wall:
				wallProd[k]++
			case isTest:
				frozenTest[k]++
				if shapeTest[k] == nil {
					shapeTest[k] = map[string]int{}
				}
				shapeTest[k][shape]++
				frozenWhere[k] = append(frozenWhere[k], fmt.Sprintf("%s:%d", path, fset.Position(pos).Line))
			default:
				frozenProd[k]++
			}
			// CREDIT THE FIELD SEAM THE OPTIONS SEAM FEEDS. The constructor is the
			// only injection point those types offer, so an options injection IS an
			// injection of the field — and the caller's file, not the constructor's,
			// still decides whether it counts as a test.
			if to, ok := credit[k]; ok {
				recordIn(to.dir, to.typ, to.field, val, pos, shape+" (via "+name+")")
			}
		}
		record := func(name, field string, val ast.Expr, pos token.Pos, shape string) {
			recordIn(filepath.Dir(path), name, field, val, pos, shape)
		}
		_ = record
		// Shape 1 — composite literal with a keyed seam field.
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}
			name := baseTypeName(cl.Type)
			seamDir, field, isSeam := resolveSeam(seam, fileImports[path], modPath, filepath.Dir(path), cl.Type, name)
			if !isSeam {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
					recordIn(seamDir, name, field, kv.Value, kv.Pos(), "literal")
				}
			}
			return true
		})
		// Shapes 2 and 3 — per function, so local variable types are in scope.
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// varType is ONE map for the whole body, so a name rebound to a
			// different type would otherwise be resolved by whichever binding the
			// walk saw last (ATTRIBUTE-AND-SAY, 2026-08-02). A CONFLICTING REBIND
			// DROPS the binding instead: the name becomes unattributable, which is
			// true, rather than attributed to an arbitrary one of its two types.
			varType := map[string]string{}
			conflicted := map[string]bool{}
			dir := filepath.Dir(path)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range as.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || i >= len(as.Rhs) {
						continue
					}
					ty := constructedType(as.Rhs[i], funcResult[dir], methodResult[dir], declaredTypes)
					if ty == "" {
						// `svc := h.svc` — a field read. Resolve h, then h's field type.
						if sel, ok := as.Rhs[i].(*ast.SelectorExpr); ok && sel.Sel != nil {
							if base, ok := sel.X.(*ast.Ident); ok {
								if bt := varType[base.Name]; bt != "" {
									ty = fieldType[dir][bt+"."+sel.Sel.Name]
								}
							}
						}
					}
					if ty == "" {
						continue
					}
					if prev, seen := varType[id.Name]; seen && prev != ty {
						conflicted[id.Name] = true
					}
					varType[id.Name] = ty
				}
				return true
			})
			for name := range conflicted {
				delete(varType, name)
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				// Shape 2 — assignment to a seam field.
				if as, ok := n.(*ast.AssignStmt); ok {
					for i, lhs := range as.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || sel.Sel == nil || i >= len(as.Rhs) {
							continue
						}
						isField := false
						for _, want := range seamFields {
							if sel.Sel.Name == want {
								isField = true
							}
						}
						if !isField {
							continue
						}
						recv, _ := sel.X.(*ast.Ident)
						typ := ""
						if recv != nil {
							typ = varType[recv.Name]
						}
						if typ != "" && seam[dir][typ] == sel.Sel.Name {
							record(typ, sel.Sel.Name, as.Rhs[i], as.Pos(), "assignment")
						} else if typ != "" {
							// RESOLVED, but the type declares no such seam — nothing to
							// attribute and NOTHING TO SUPPRESS. Widening suppression to
							// the field name here would let an unrelated struct blank the
							// verdict for every seam sharing the name (ATTRIBUTE-AND-SAY).
						} else if !isWallClock(as.Rhs[i]) {
							key := dir + "." + sel.Sel.Name
							if isTest {
								unattributedTest[key]++
							} else {
								unattributedProd[key]++
							}
							unattributedWhere[key] = append(unattributedWhere[key],
								fmt.Sprintf("%s:%d", path, fset.Position(as.Pos()).Line))
						}
					}
				}
				// Shape 3 — a clock handed to an option/constructor call.
				if call, ok := n.(*ast.CallExpr); ok {
					for _, arg := range call.Args {
						// A CLOCK ARGUMENT IS NOT ALWAYS A LITERAL. This required
						// `arg.(*ast.FuncLit)`, so `WithClock(fixedClock(now))` — a helper
						// that RETURNS a clock — was invisible, and
						// internal/auth/sessionstore's six frozen tests read as zero.
						// A call counts when the callee's DECLARED result is a clock func;
						// whether it is the wall clock is judged from the closure that
						// callee returns, not assumed either way.
						if !argIsFrozenClock(arg, funcDecl[dir], isWallClock) {
							continue
						}
						// A POSITIONAL CLOCK INTO A CONSTRUCTOR IS AN INJECTION INTO THE
						// TYPE IT CONSTRUCTS (ATTRIBUTE-AND-SAY, 2026-08-02). It used to
						// land in the option bucket, where it counted for nothing and
						// left the constructed seam looking untouched.
						built := constructedType(call, funcResult[dir], methodResult[dir], declaredTypes)
						// Cross-package too: `org.NewClaimStore(pool, clk)` names its
						// package in the callee's selector, and the seam lives there,
						// not in the caller's directory.
						if bd, field, isSeam := resolveSeam(seam, fileImports[path], modPath, dir, callPkgType(call, built), built); isSeam {
							recordIn(bd, built, field, arg, call.Pos(), "positional")
							continue
						}
						// AN OPTION CALL IS AN INJECTION (OPTION-CALL-IS-THE-INJECTION,
						// 2026-08-02). `optionInject` was printed in a section of its own
						// and never consulted by the verdict, so a seam whose ONLY
						// injection path is an option call was reported NEVER INJECTED.
						// identuum-ag-oss sets six Service seams exclusively through
						// `WithClock`, and tests call it — those seams were frozen and
						// listed as untouched.
						//
						// The callee is resolved, not guessed: a same-package func whose
						// body RETURNS A CLOSURE taking one pointer parameter names its
						// receiver in that parameter's type. TEST or PRODUCTION is decided
						// by the CALLER's file, so WithClock's own body stays plumbing while
						// a test calling it counts.
						if recv := optionReceiverType(funcDecl[dir][calleeName(call.Fun)]); recv != "" {
							if field, isSeam := seam[dir][recv]; isSeam {
								record(recv, field, arg, call.Pos(), "option")
								continue
							}
						}
						optionInject[calleeName(call.Fun)]++
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "clockfuse: %v\n", err)
		os.Exit(2)
	}

	// Each seam is now named WITH ITS PACKAGE, because two structs called Service
	// in different packages are two seams and used to print as one.
	// refs reuses seamKey rather than declaring a twin: staticcheck flagged the
	// duplicate (S1016), and one type for "which seam" is also simply correct.
	var refs []seamKey
	for d, m := range seam {
		for ty, fld := range m {
			refs = append(refs, seamKey{d, ty, fld})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].dir != refs[j].dir {
			return refs[i].dir < refs[j].dir
		}
		return refs[i].typ < refs[j].typ
	})
	fmt.Printf("clockfuse: %d seam-bearing struct(s) across %d package(s)\n", len(refs), len(seam))

	// THE CENSUS, printed for every seam and not only for the failures: a reader
	// checking "is this seam used?" must be able to see the answer, not infer it
	// from the absence of a complaint. That inference is the defect this pass
	// exists for.
	fmt.Println("clockfuse: seam injection census (non-wall-clock injections are the ones that matter):")
	fmt.Println("  counted in three shapes: composite-literal key, assignment (x.now = ...), and option/positional call")
	var unused, undecided []string
	var unusedRefs []seamKey // the same seams, structured, for the D/S classification
	for _, r := range refs {
		k := r
		via := ""
		if shapes := shapeTest[k]; len(shapes) > 0 {
			names := make([]string, 0, len(shapes))
			for s, n := range shapes {
				names = append(names, fmt.Sprintf("%s x%d", s, n))
			}
			sort.Strings(names)
			via = "  via " + strings.Join(names, ", ")
		}
		fmt.Printf("  %s.%s.%s: TEST %d frozen / %d wall  |  PRODUCTION %d frozen / %d wall%s\n",
			r.dir, r.typ, r.field, frozenTest[k], wallTest[k], frozenProd[k], wallProd[k], via)
		// THE VERDICT IS CONSERVATIVE ON PURPOSE. An assignment whose receiver type
		// could not be resolved from the AST might be to THIS seam, so a field with
		// unattributed assignments disqualifies every seam sharing its name from the
		// never-injected list. Over-reporting "never injected" is the failure that
		// made the previous census false; under-reporting is visible and checkable.
		// ONLY A TEST INJECTION CLEARS A SEAM (NAME-COLLIDES-AND-PLUMBING-COUNTS,
		// 2026-08-02). The pass walks every .go file, so four identuum-idp-oss
		// constructors writing `now: now` right after `if now == nil { now = time.Now }`
		// counted as FROZEN — production PLUMBING marking its own seam exercised. I
		// refused that exact shape one repo over, for an option setter, and then let
		// it through here. A production unattributed assignment likewise suppresses
		// nothing: identuum-ag-oss's lone UNDECIDED was WithClock's own body.
		switch {
		case frozenTest[k] > 0:
			// exercised by a test — nothing to say
		case unattributedTest[r.dir+"."+r.field] > 0:
			undecided = append(undecided, fmt.Sprintf("%s.%s.%s", r.dir, r.typ, r.field))
		default:
			unused = append(unused, fmt.Sprintf("%s.%s.%s", r.dir, r.typ, r.field))
			unusedRefs = append(unusedRefs, r)
		}
	}
	if len(unattributedTest)+len(unattributedProd) > 0 {
		keys := map[string]bool{}
		for f := range unattributedTest {
			keys[f] = true
		}
		for f := range unattributedProd {
			keys[f] = true
		}
		fields := make([]string, 0, len(keys))
		for f := range keys {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		fmt.Println("clockfuse: assignments whose receiver type could not be resolved from the AST:")
		for _, f := range fields {
			fmt.Printf("  %s = <non-wall clock>  TEST x%d / PRODUCTION x%d\n", f, unattributedTest[f], unattributedProd[f])
			for _, w := range unattributedWhere[f] {
				fmt.Printf("      %s\n", w)
			}
		}
		fmt.Println("  Only the TEST ones shadow a verdict, and only within their own package. A")
		fmt.Println("  production one is plumbing — it can no more exercise a seam than declare it.")
	}
	if len(optionInject) > 0 {
		callees := make([]string, 0, len(optionInject))
		for c := range optionInject {
			callees = append(callees, c)
		}
		sort.Strings(callees)
		fmt.Println("clockfuse: clocks handed to option/constructor calls (no struct field to attribute to):")
		for _, c := range callees {
			fmt.Printf("  %s(... a non-wall clock ...) x%d\n", c, optionInject[c])
		}
	}
	// THE CAPS LINE CARRIES ITS OWN CAVEAT (ATTRIBUTE-AND-SAY, 2026-08-02). This
	// sentence is what a reader greps for, and it used to read clean while ~20 seams
	// were UNDECIDED — suppressed by unattributable assignments reported four lines
	// away. A headline that omits what it could not decide is a headline that lies
	// by omission, so the undecided count is now inside it.
	// PRINTED UNCONDITIONALLY, INCLUDING AT ZERO (OPTION-CALL-IS-THE-INJECTION,
	// 2026-08-02). This line used to be suppressed when both counts were zero, and
	// that absence has now misled twice: it produced the false wiki pin "no
	// seam-bearing struct here" for identuum-ag-ce, and in this slice a build
	// failure left every repo printing nothing, which reads identically to a clean
	// result. A verdict that is invisible when it is good cannot be told apart from
	// a verdict that never ran.
	fmt.Printf("clockfuse: %d DECLARED SEAM(S) HAVE NEVER BEEN INJECTED WITH ANYTHING BUT THE WALL CLOCK; %d UNDECIDED\n",
		len(unused), len(undecided))
	if len(undecided) > 0 {
		fmt.Printf("  UNDECIDED (%d) — an unattributable assignment to the same field name may be theirs:\n", len(undecided))
		for _, u := range undecided {
			fmt.Printf("    %s\n", u)
		}
	}
	if len(unused) > 0 {
		for _, u := range unused {
			fmt.Printf("  %s -> the field exists, defaults to time.Now, and no construction site has ever frozen it\n", u)
		}
		fmt.Println("  This is a SEPARATE FINDING from the omitted-field one above. An omission means a")
		fmt.Println("  construction site skipped an available seam; this means the seam has never done its")
		fmt.Println("  job at all, and passes 1-2 report nothing for it either way.")
	}

	// THE D/S SPLIT, AND THE GATE THAT RUNS ON IT (ONE-BLOCKER, 2026-08-02).
	//
	// Only the DEADLINE half is gateable. A STAMP seam writes the clock into an
	// audit row or a latency figure: injecting it makes a field predictable, and
	// nothing decides differently when it is wrong. A DEADLINE seam is compared
	// against a stored instant, so with no injection there is no way to stand on
	// the boundary at all — that is a hole in the suite, and it is what fails here.
	deadlineSeams := []string{}
	if len(unusedRefs) > 0 {
		fmt.Println("clockfuse: the never-injected seams, split DEADLINE / STAMP:")
		for _, r := range unusedRefs {
			var holders []seamHolder
			for key, ft := range fieldType[r.dir] {
				if ft != r.typ {
					continue
				}
				dot := strings.LastIndex(key, ".")
				if dot < 0 {
					continue
				}
				holderType, holderField := key[:dot], key[dot+1:]
				if ms := methodsOf[r.dir+"."+holderType]; len(ms) > 0 {
					holders = append(holders, seamHolder{field: holderField, methods: ms})
				}
			}
			kind, sites := classifySeam(methodsOf[r.dir+"."+r.typ], r.field, fset, callables, holders)
			name := fmt.Sprintf("%s.%s.%s", r.dir, r.typ, r.field)
			switch kind {
			case "DEADLINE":
				deadlineSeams = append(deadlineSeams, name)
				fmt.Printf("  DEADLINE %s — compared at: %s\n", name, strings.Join(sites, ", "))
			case "NO-READ":
				fmt.Printf("  NO-READ  %s — no method on this receiver reads it\n", name)
			default:
				fmt.Printf("  STAMP    %s — %d clock read(s), none compared against an instant\n", name, len(sites))
			}
		}
		fmt.Println("  NO-READ means no METHOD on the receiver reads the field. For an Options struct")
		fmt.Println("  that is expected — its constructor reads it. For a service struct it means the")
		fmt.Println("  seam is DEAD: declared, defaulted, assigned, and then never consulted.")
	}
	if len(deadlineSeams) > 0 {
		fmt.Printf("clockfuse: GATE — %d DEADLINE seam(s) have never been injected. This FAILS the build:\n", len(deadlineSeams))
		for _, d := range deadlineSeams {
			fmt.Printf("    %s\n", d)
		}
		fmt.Println("  Each compares a clock read against a stored instant, and no test has ever")
		fmt.Println("  frozen it — so no test can stand on its boundary. Inject it from a test, or")
		fmt.Println("  delete the seam. There is no allowlist.")
		os.Exit(3)
	}

	if len(mixed) > 0 {
		sort.Slice(mixed, func(i, j int) bool { return mixed[i].pos < mixed[j].pos })
		fmt.Printf("clockfuse: %d test func(s) FREEZE a clock and yet pass the WALL clock positionally:\n", len(mixed))
		for _, m := range mixed {
			fmt.Printf("  %s: %s(... time.Now ...) inside a func that also calls time.Date -> two clocks in one scope\n", m.pos, m.typ)
		}
	}

	if len(optless) > 0 {
		sort.Slice(optless, func(i, j int) bool { return optless[i].pos < optless[j].pos })
		fmt.Printf("clockfuse: %d test construction(s) OMIT the clock option while the enclosing func freezes a clock:\n", len(optless))
		for _, o := range optless {
			fmt.Printf("  %s: %s(...) for %s omits its With* clock option -> falls back to the wall clock\n", o.pos, o.typ, o.field)
		}
	}

	if len(found) == 0 && len(mixed) == 0 && len(optless) == 0 {
		fmt.Println("clockfuse: no test literal omits its clock seam. CLEAN.")
		return
	}
	if len(found) == 0 {
		os.Exit(1)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].pos < found[j].pos })
	fmt.Printf("clockfuse: %d test literal(s) omit their clock seam — each needs triage (FUSE or BENIGN):\n", len(found))
	for _, f := range found {
		fmt.Printf("  %s: %s{...} omits `%s` -> falls back to the wall clock\n", f.pos, f.typ, f.field)
	}
	os.Exit(1)
}

// optionTarget reports the struct type an option function configures, when its
// body is `return func(x *T) { x.<seam> = <param> }`. Returns "" otherwise.
func optionTarget(fd *ast.FuncDecl) string {
	if len(fd.Body.List) != 1 {
		return ""
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return ""
	}
	fl, ok := ret.Results[0].(*ast.FuncLit)
	if !ok || fl.Type.Params == nil || len(fl.Type.Params.List) != 1 || fl.Body == nil {
		return ""
	}
	target := baseTypeName(fl.Type.Params.List[0].Type)
	if target == "" {
		return ""
	}
	assigns := false
	ast.Inspect(fl.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil {
				continue
			}
			for _, sf := range seamFields {
				if sel.Sel.Name == sf {
					assigns = true
				}
			}
		}
		return true
	})
	if !assigns {
		return ""
	}
	return target
}

// baseTypeName strips pointers and package qualifiers from a type expression.
func baseTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if t.Sel != nil {
			return t.Sel.Name
		}
	}
	return ""
}

// calleeName returns the bare function name of a call target, ignoring any
// package qualifier, so pkg.NewService and NewService match alike.
func calleeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if t.Sel != nil {
			return t.Sel.Name
		}
	}
	return ""
}

// freezesClock reports whether a body contains a hardcoded time.Date(...).
func freezesClock(body *ast.BlockStmt) bool {
	frozen := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Date" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" {
			frozen = true
		}
		return true
	})
	return frozen
}

// constructedType names the type a local variable was built from, so that
// `svc.now = ...` can be attributed to the struct that declares `now`. Four
// shapes, all answerable from the AST — deliberately NOT go/types, because the
// question here is "what did this expression syntactically construct", and the
// declared result of a same-package function answers it exactly:
//
//	&Foo{...} / Foo{...}          composite literal
//	NewFoo(...) / newFoo(...)     constructor by naming convention
//	newFooHarness(t)              same-package func, DECLARED result type
//	newFooHarness(t).WithX(y)     method chain, DECLARED result type
//
// The last two were the three unattributed sites. Returns "" when it cannot tell,
// and the caller records that rather than guessing: a wrong attribution is worse
// than a missing one, because it makes a seam look exercised.
func constructedType(e ast.Expr, funcRes, methodRes map[string]string, declared map[string]bool) string {
	switch v := e.(type) {
	case *ast.UnaryExpr:
		return constructedType(v.X, funcRes, methodRes, declared)
	case *ast.CompositeLit:
		return baseTypeName(v.Type)
	case *ast.CallExpr:
		switch fun := v.Fun.(type) {
		case *ast.Ident:
			if res, ok := funcRes[fun.Name]; ok {
				return res
			}
			return newPrefixType(fun.Name, declared)
		case *ast.SelectorExpr:
			if fun.Sel != nil {
				// A chain: resolve the receiver, then that type's method result.
				if recvType := constructedType(fun.X, funcRes, methodRes, declared); recvType != "" {
					if res, ok := methodRes[recvType+"."+fun.Sel.Name]; ok {
						return res
					}
				}
				return newPrefixType(fun.Sel.Name, declared)
			}
		}
	}
	return ""
}

// newPrefixType applies the New<Type> / new<Type> naming convention — but ONLY
// when the name it derives is a type that actually exists in the package.
//
// UNGATED, THIS HEURISTIC INVENTS TYPES AND THE INVENTED ONE POISONS A REAL
// BINDING. A test helper closure named `newCase` yielded the "type" Case; the
// same variable was also bound to a genuine *AuthorizeService inside that
// closure, the two disagreed, and the conflict rule — correctly, given what it
// was told — dropped the binding entirely. The seam then read NEVER INJECTED
// with FIVE other seams shadowed into UNDECIDED by one unattributable write.
// Found while pinning that very seam: the test looked wrong, the tool was.
func newPrefixType(name string, declared map[string]bool) string {
	for _, prefix := range []string{"New", "new"} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			cand := name[len(prefix):]
			if declared[cand] {
				return cand
			}
			return ""
		}
	}
	return ""
}

// optionReceiverType names the struct a functional option configures, by reading
// the closure it returns: `func WithClock(now func() time.Time) ServiceOption {
// return func(s *Service) { s.now = now } }` names *Service in that closure's sole
// parameter. Returns "" for anything that is not that shape.
//
// This is what makes an OPTION CALL attributable. The option's own body remains
// production plumbing — it is the CALLER that injects, and the caller's file
// decides whether the injection counts as a test.
func optionReceiverType(fd *ast.FuncDecl) string {
	if fd == nil || fd.Body == nil {
		return ""
	}
	found := ""
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		fl, ok := ret.Results[0].(*ast.FuncLit)
		if !ok || fl.Type == nil || fl.Type.Params == nil || len(fl.Type.Params.List) != 1 {
			return true
		}
		if star, ok := fl.Type.Params.List[0].Type.(*ast.StarExpr); ok {
			if name := baseTypeName(star.X); name != "" {
				found = name
			}
		}
		return true
	})
	return found
}

// argIsFrozenClock reports whether an argument supplies a clock that can be
// frozen — a `func() time.Time` that is not the wall clock. Two shapes:
//
//	WithClock(func() time.Time { return t0 })   a literal
//	WithClock(fixedClock(now))                  a helper RETURNING one
//
// For the helper the DECLARED result type decides that it is a clock, and the
// closure its body returns decides whether that clock is the wall clock. Nothing
// is assumed in either direction: an unresolvable callee returns false, so a
// missed injection shows up as a seam still listed rather than as a false clear.
//
// isWallClock is passed in because it is a closure inside main; calling it from
// package scope is a compile error, and the first version of this helper did
// exactly that. The tool then printed nothing and every verdict line came back
// EMPTY — which is the suppressed-line trap from the previous slice, this time
// caused by a build failure. Read the output, not the absence of it.
func argIsFrozenClock(arg ast.Expr, decls map[string]*ast.FuncDecl, isWallClock func(ast.Expr) bool) bool {
	if fl, ok := arg.(*ast.FuncLit); ok {
		return fl.Type != nil && isClockFunc(fl.Type) && !isWallClock(arg)
	}
	call, ok := arg.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	fd := decls[id.Name]
	if fd == nil || fd.Type == nil || fd.Type.Results == nil || len(fd.Type.Results.List) != 1 {
		return false
	}
	if !isClockFunc(fd.Type.Results.List[0].Type) {
		return false
	}
	// The callee is a clock factory. Is the clock it returns the wall clock?
	wall := false
	if fd.Body != nil {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return true
			}
			if isWallClock(ret.Results[0]) {
				wall = true
			}
			return true
		})
	}
	return !wall
}

// readsSelector reports whether body contains `name.field`.
func readsSelector(body *ast.BlockStmt, name, field string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != field {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// writesField reports whether body sets `field` on a value of type typ — as a
// keyed element of a composite literal, or as an assignment to a selector.
func writesField(body *ast.BlockStmt, typ, field string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CompositeLit:
			if baseTypeName(v.Type) != typ {
				return true
			}
			for _, elt := range v.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
					found = true
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == field {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// resolveSeam finds the directory whose seam table owns this composite literal's
// type. A bare `Options{...}` belongs to the file's own directory; a qualified
// `mfa.ServiceOptions{...}` is resolved through THE FILE'S IMPORT BLOCK — the
// qualifier is looked up there, and the import path is turned back into a
// directory by stripping the module path.
//
// NOT through a package NAME. That lookup was ambiguous (six names in two
// directories each in identuum-idp-oss) and took whichever matched first, so a
// finding could be redirected — and a gate silenced — BY ADDING A FILE.
func resolveSeam(seam map[string]map[string]string, imports map[string]string, modPath, here string, typ ast.Expr, name string) (string, string, bool) {
	if f, ok := seam[here][name]; ok {
		return here, f, true
	}
	sel, ok := typ.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	ip, ok := imports[pkg.Name]
	if !ok || modPath == "" || !strings.HasPrefix(ip, modPath) {
		return "", "", false
	}
	d := strings.TrimPrefix(strings.TrimPrefix(ip, modPath), "/")
	if d == "" {
		d = "."
	}
	if f, ok := seam[d][name]; ok {
		return d, f, true
	}
	return "", "", false
}

// modulePath reads the module path from go.mod so an import path can be turned
// back into a directory. Returns "" when it cannot be read, which makes every
// qualified lookup fail closed rather than resolve somewhere arbitrary.
func modulePath(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// callPkgType rebuilds a qualified type expression for a constructor call, so
// resolveSeam can find the package that owns the constructed type. `org.NewX(...)`
// yields `org.X`; an unqualified call yields a bare ident and resolves locally.
func callPkgType(call *ast.CallExpr, built string) ast.Expr {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			return &ast.SelectorExpr{X: ast.NewIdent(pkg.Name), Sel: ast.NewIdent(built)}
		}
	}
	return ast.NewIdent(built)
}

// SEAM CLASSIFICATION — DEADLINE vs STAMP (ONE-BLOCKER, 2026-08-02).
//
// `x := s.now().Sub(t)` IS A DURATION, NOT A DEADLINE. The classifier this
// replaces was an uncommitted script that counted any `.Sub(` as a comparison,
// and — worse — attributed comparisons PER PACKAGE, so every seam in a package
// inherited the deadlines of its neighbours. Both defects pointed the same way:
// at seams that gate nothing. `backchannellogout.DeliveryService.now`, whose
// only arithmetic is `latency := s.now().Sub(started)`, came back DEADLINE
// against its own adjudication; `org.ClaimService.now`, which no method reads at
// all, inherited `ClaimStore`'s `!s.now().Before(t.ExpiresAt)` next door.
//
// So a Sub is followed to its RESULT: a duration only makes a deadline when it
// is COMPARED, directly or through the variable it lands in. And a comparison is
// only this seam's when it is reached from a read of THIS field on THIS receiver.
//
// KNOWN BLIND SPOTS, stated because a gate that hides them is worse than none:
// a read handed to another function and compared there reads as STAMP; so does a
// seam reached through an aliased receiver. Both under-report, which fails open —
// the direction that lets a real deadline through, not the one that blocks a
// clean repo. Whichever way a future revision moves, it moves the verdict.

// maxHops CAPS THE INTERPROCEDURAL FOLLOW AT THREE CALLS. The seam read is
// followed from the method that reads it, into a callee, into ITS callee — and
// no further. THE CAP IS THE HONEST LIMIT OF THIS TOOL: three is where the
// deepest real chain in the fleet sits (a handler hands its clock to a store,
// the store asks a record, the record compares), and each extra hop multiplies
// name-matched candidates without a type checker to prune them. A seam whose
// comparison sits FOUR calls away still reads STAMP, and no output says so.
const maxHops = 3

// instantOps carry a clock-derived time.Time through to another value; the Unix
// family projects it to a number that is then compared, which is still the same
// deadline wearing a different type.
var instantOps = map[string]bool{
	"UTC": true, "Local": true, "In": true, "Add": true, "AddDate": true,
	"Round": true, "Truncate": true,
	"Unix": true, "UnixNano": true, "UnixMilli": true, "UnixMicro": true,
}

// instantCmp are the time.Time comparisons. A deadline is exactly one of these
// with a clock-derived instant on one side of it.
var instantCmp = map[string]bool{"After": true, "Before": true, "Equal": true}

func isCmpOp(op token.Token) bool {
	switch op {
	case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL, token.NEQ:
		return true
	}
	return false
}

// seamFlow tracks which values in one method body came from one seam.
type seamFlow struct {
	recv, field string
	via         string          // when set, the seam lives at <recv>.<via>.<field>
	accessor    map[string]bool // same-receiver methods that RETURN the seam value
	recvAlias   map[string]bool // idents that ARE the receiver (`s2 := s`)
	clockFn     map[string]bool // idents bound to the seam FUNCTION (`f := s.now`)
	instantVar  map[string]bool // locals holding a clock-derived instant
	durVar      map[string]bool // locals holding a duration derived from it
}

// newSeamFlowVia builds a flow whose read shape is `<recv>.<via>.<field>()` —
// the seam reached through ONE struct field of the receiver.
func newSeamFlowVia(recv, via, field string) *seamFlow {
	sf := newSeamFlow(recv, field)
	sf.via = via
	return sf
}

func newSeamFlow(recv, field string) *seamFlow {
	sf := &seamFlow{
		recv: recv, field: field,
		accessor:   map[string]bool{},
		recvAlias:  map[string]bool{},
		clockFn:    map[string]bool{},
		instantVar: map[string]bool{},
		durVar:     map[string]bool{},
	}
	if recv != "" {
		sf.recvAlias[recv] = true
	}
	return sf
}

// isSeamRead reports whether e is literally `<recv>.<field>()`.
func (sf *seamFlow) isSeamRead(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	// `f()` where f was bound to the seam: `f := s.now`.
	if id, ok := call.Fun.(*ast.Ident); ok {
		return sf.clockFn[id.Name]
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	// `s.timeNow()` — the seam behind a SAME-RECEIVER ACCESSOR. identuum-ag-oss
	// writes `func (s *Service) timeNow() time.Time { if s.now != nil { return
	// s.now() }; return time.Now().UTC() }` and every caller reads THAT. The seam
	// read and the comparison then sit in different methods, so a per-method scan
	// sees a read that is never compared and a comparison with no read — which is
	// why all five of that repo's seams classified STAMP while agentsession
	// compares `!row.ExpiresAt.After(s.timeNow())` in plain Go.
	if sf.accessor[sel.Sel.Name] {
		if id, ok := sel.X.(*ast.Ident); ok && sf.recvAlias[id.Name] {
			return true
		}
	}
	if sel.Sel.Name != sf.field {
		return false
	}
	// `s.deps.Now()` — the seam reached through ONE struct field of the receiver.
	if sf.via != "" {
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != sf.via {
			return false
		}
		id, ok := inner.X.(*ast.Ident)
		return ok && sf.recvAlias[id.Name]
	}
	// `s.now()` OR `s2.now()` where `s2 := s`.
	id, ok := sel.X.(*ast.Ident)
	return ok && sf.recvAlias[id.Name]
}

// isSeamValueRef reports whether e HANDS THE SEAM ON without calling it —
// `Now: h.now` in a composite literal, or `f(h.now)` as an argument. That is a
// use of the seam: the clock reaches somebody else and gets called there.
func (sf *seamFlow) isSeamValueRef(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != sf.field {
		return false
	}
	if sf.via != "" {
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != sf.via {
			return false
		}
		id, ok := inner.X.(*ast.Ident)
		return ok && sf.recvAlias[id.Name]
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && sf.recvAlias[id.Name]
}

// isSeamFuncRef reports whether e is the seam FUNCTION itself, unresolved —
// `s.now` with no call parens, the value an alias binds to.
func (sf *seamFlow) isSeamFuncRef(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != sf.field {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && sf.recvAlias[id.Name]
}

// isRecvRef reports whether e is the receiver, or an ident already known to be
// an alias of it.
func (sf *seamFlow) isRecvRef(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && sf.recvAlias[id.Name]
}

func (sf *seamFlow) isInstant(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return sf.instantVar[x.Name]
	case *ast.ParenExpr:
		return sf.isInstant(x.X)
	case *ast.CallExpr:
		if sf.isSeamRead(x) {
			return true
		}
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && instantOps[sel.Sel.Name] {
			return sf.isInstant(sel.X)
		}
	}
	return false
}

// isDuration reports whether e is a duration PRODUCED BY this seam — the value
// `s.now().Sub(t)` yields, and anything arithmetic carries it into.
func (sf *seamFlow) isDuration(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return sf.durVar[x.Name]
	case *ast.ParenExpr:
		return sf.isDuration(x.X)
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if sel.Sel.Name == "Sub" && len(x.Args) == 1 {
			return sf.isInstant(sel.X) || sf.isInstant(x.Args[0])
		}
		if sel.Sel.Name == "Round" || sel.Sel.Name == "Truncate" {
			return sf.isDuration(sel.X)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD || x.Op == token.SUB || x.Op == token.MUL || x.Op == token.QUO {
			return sf.isDuration(x.X) || sf.isDuration(x.Y)
		}
	}
	return false
}

// collect walks assignments to a fixed point, so a value that reaches a
// comparison through two hops of locals is still this seam's value.
func (sf *seamFlow) collect(body *ast.BlockStmt) {
	for i := 0; i < 8; i++ {
		changed := false
		note := func(lhs []ast.Expr, rhs []ast.Expr) {
			if len(lhs) != len(rhs) {
				return
			}
			for k, l := range lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				// ALIASES FIRST: `s2 := s` and `f := s.now` both make later reads
				// through the alias invisible to a plain <recv>.<field>() match.
				if sf.isRecvRef(rhs[k]) && !sf.recvAlias[id.Name] {
					sf.recvAlias[id.Name] = true
					changed = true
				}
				if sf.isSeamFuncRef(rhs[k]) && !sf.clockFn[id.Name] {
					sf.clockFn[id.Name] = true
					changed = true
				}
				if sf.isInstant(rhs[k]) && !sf.instantVar[id.Name] {
					sf.instantVar[id.Name] = true
					changed = true
				}
				if sf.isDuration(rhs[k]) && !sf.durVar[id.Name] {
					sf.durVar[id.Name] = true
					changed = true
				}
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				note(x.Lhs, x.Rhs)
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, 0, len(x.Names))
				for _, nm := range x.Names {
					lhs = append(lhs, nm)
				}
				note(lhs, x.Values)
			}
			return true
		})
		if !changed {
			return
		}
	}
}

// seamHolder is a type that HOLDS the seam's struct in one of its fields, with
// the methods that might read through it.
type seamHolder struct {
	field   string // the field on the holder whose type is the seam's struct
	methods []*ast.FuncDecl
}

// cmpSites returns every comparison in body that this flow's values reach.
func (sf *seamFlow) cmpSites(body *ast.BlockStmt, fset *token.FileSet) []string {
	var hits []string
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || !instantCmp[sel.Sel.Name] || len(x.Args) != 1 {
				return true
			}
			if sf.isInstant(sel.X) || sf.isInstant(x.Args[0]) {
				hits = append(hits, fmt.Sprintf("%s .%s()", fset.Position(x.Pos()), sel.Sel.Name))
			}
		case *ast.BinaryExpr:
			if !isCmpOp(x.Op) {
				return true
			}
			// A DURATION COMPARED AGAINST THE LITERAL ZERO IS A SIGN CHECK, NOT A
			// DEADLINE. `if latency < 0 { latency = 0 }` in DeliveryService.emitAudit
			// clamps a measured figure before it is written to an audit row; it decides
			// nothing about whether anything has elapsed. Only a comparison against a
			// real bound — a TTL, a freshness window — can express staleness, and that
			// bound is never the zero literal.
			if isZeroLit(x.X) || isZeroLit(x.Y) {
				if sf.isDuration(x.X) || sf.isDuration(x.Y) {
					return true
				}
			}
			if sf.isInstant(x.X) || sf.isInstant(x.Y) || sf.isDuration(x.X) || sf.isDuration(x.Y) {
				hits = append(hits, fmt.Sprintf("%s %s", fset.Position(x.Pos()), x.Op))
			}
		}
		return true
	})
	return hits
}

// paramCmpSites seeds parameter k of fd with the seam's value and reports the
// comparisons it reaches — one hop past the call site.
func paramCmpSites(fd *ast.FuncDecl, k int, asDuration bool, fset *token.FileSet, callables map[string][]*ast.FuncDecl, depth int) []string {
	if fd.Body == nil || fd.Type == nil || fd.Type.Params == nil {
		return nil
	}
	var names []string
	var types []ast.Expr
	for _, f := range fd.Type.Params.List {
		if _, variadic := f.Type.(*ast.Ellipsis); variadic {
			return nil // positional indexing stops meaning anything
		}
		if len(f.Names) == 0 {
			names = append(names, "_")
			types = append(types, f.Type)
			continue
		}
		for _, nm := range f.Names {
			names = append(names, nm.Name)
			types = append(types, f.Type)
		}
	}
	if k >= len(names) || names[k] == "_" {
		return nil
	}
	// THE PARAMETER MUST ACTUALLY BE A TIME VALUE. Resolving candidates by name
	// alone matched all six `Consume` declarations in package par, including
	// `Service.Consume(ctx, requestURI, expectedClientID string)` — whose third
	// parameter is a STRING, and whose `expectedClientID != ""` was being reported
	// as a clock comparison. The type is right there in the AST; a name is not
	// enough to justify following a call.
	want := "Time"
	if asDuration {
		want = "Duration"
	}
	if !isTimePkgType(types[k], want) {
		return nil
	}
	sf := newSeamFlow("", "\x00")
	if asDuration {
		sf.durVar[names[k]] = true
	} else {
		sf.instantVar[names[k]] = true
	}
	sf.collect(fd.Body)
	hits := sf.cmpSites(fd.Body, fset)
	if depth > 0 {
		hits = append(hits, followArgs(fd.Body, sf, fset, callables, depth-1)...)
	}
	return hits
}

// followArgs carries the seam's values into the calls they are passed to, and
// reports the comparisons found there.
//
// DEPTH 2, NOT 1. `h.refreshStore.Consume(ctx, raw, now)` hands the clock to a
// store whose body then asks `entry.IsExpired(at)` — the comparison is TWO hops
// from the seam, and at depth 1 identuum-idp-ce's par.TokenHandler.now read STAMP
// with the refresh-token expiry decision sitting right there. Hand-checked
// against the four Consume implementations on disk, every one of which compares
// its `at` through IsExpired.
func followArgs(body *ast.BlockStmt, sf *seamFlow, fset *token.FileSet, callables map[string][]*ast.FuncDecl, depth int) []string {
	var hits []string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeIdent(call.Fun)
		if name == "" || instantCmp[name] || instantOps[name] || name == "Sub" {
			return true
		}
		for k, arg := range call.Args {
			dur := sf.isDuration(arg)
			if !dur && !sf.isInstant(arg) {
				continue
			}
			for _, cand := range callables[name] {
				for _, h := range paramCmpSites(cand, k, dur, fset, callables, depth) {
					hits = append(hits, h+" (via "+name+")")
				}
			}
		}
		return true
	})
	return hits
}

// calleeIdent names the function a call targets, whether plain or selected.
func calleeIdent(fun ast.Expr) string {
	switch x := fun.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// classifySeam returns DEADLINE, STAMP or NO-READ for one seam, plus the sites
// that decided it.
//
// IT FOLLOWS THE READ UP TO maxHops CALLS, ACROSS PACKAGE BOUNDARIES, AND
// THROUGH ALIASES OF THE RECEIVER. Every one of those three was a blind spot
// this tool NAMED IN ITS OWN COMMENT while the gate ran green on top of it, and
// the seam that proved they mattered — par.TokenHandler.now, the refresh-token
// expiry — was found BY HAND, not by the detector. Concretely:
//
//	depth      `h.store.Consume(ctx, raw, now)` -> `entry.IsExpired(at)` -> `!at.Before(exp)`
//	package    the seam is in par; the store that compares its clock is in oauth
//	alias      `s2 := s; s2.now()` and `f := s.now; f()` both hid the read entirely
//
// Candidates resolve BY NAME MODULE-WIDE, since the receiver's type is what the
// AST cannot give us at the call site. What keeps that honest is the parameter
// TYPE guard: a candidate is only followed when its k-th parameter is really a
// time.Time or time.Duration. Two same-named functions that both take a time at
// the same position would over-report — the fail-CLOSED direction, which blocks
// rather than waves through.
//
// WHAT REMAINS, stated because a gate that hides its limits is worse than none:
// a comparison more than maxHops calls away, and a clock stored into a struct
// field and compared from there. Both under-report, which fails OPEN.
func classifySeam(methods []*ast.FuncDecl, field string, fset *token.FileSet, callables map[string][]*ast.FuncDecl, holders []seamHolder) (string, []string) {
	reads, cmps := 0, []string{}
	// A same-receiver method whose body READS the seam and RETURNS a time is an
	// accessor: calling it IS reading the seam.
	accessors := map[string]bool{}
	for _, fd := range methods {
		if fd.Name == nil || fd.Body == nil || fd.Type == nil || fd.Type.Results == nil {
			continue
		}
		if len(fd.Type.Results.List) != 1 || !isTimePkgType(fd.Type.Results.List[0].Type, "Time") {
			continue
		}
		if len(fd.Recv.List[0].Names) == 0 {
			continue
		}
		probe := newSeamFlow(fd.Recv.List[0].Names[0].Name, field)
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && probe.isSeamRead(e) {
				found = true
			}
			return true
		})
		if found {
			accessors[fd.Name.Name] = true
		}
	}
	scan := func(fd *ast.FuncDecl, via string) {
		if len(fd.Recv.List[0].Names) == 0 {
			return // `func (T) M()` cannot read a field
		}
		sf := newSeamFlowVia(fd.Recv.List[0].Names[0].Name, via, field)
		sf.accessor = accessors
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			// A CALL and a HAND-OFF ARE BOTH READS. `Now: h.now` puts the seam in
			// somebody else's struct, where it is called; counting only `h.now()`
			// reported that field as NO-READ, which reads as "dead" and is not.
			if sf.isSeamRead(e) || sf.isSeamValueRef(e) {
				reads++
			}
			return true
		})
		sf.collect(fd.Body)
		cmps = append(cmps, sf.cmpSites(fd.Body, fset)...)
		cmps = append(cmps, followArgs(fd.Body, sf, fset, callables, maxHops-1)...)
	}
	for _, fd := range methods {
		scan(fd, "")
	}
	// THE SEAM READ THROUGH ONE STRUCT FIELD OF ANOTHER TYPE. `s.deps.Now()` in
	// identuum-idp-oss internal/setup is a real use that a receiver-scoped check
	// cannot see: the field lives on Deps, the read happens in a method of Service,
	// and Service merely HOLDS a Deps. Without this the seam reports NO-READ.
	for _, h := range holders {
		for _, fd := range h.methods {
			scan(fd, h.field)
		}
	}
	switch {
	case len(cmps) > 0:
		return "DEADLINE", cmps
	case reads == 0:
		return "NO-READ", nil
	default:
		return "STAMP", make([]string, reads)
	}
}

// isZeroLit reports whether e is the untyped literal 0.
func isZeroLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

// isTimePkgType reports whether e names time.<want>.
func isTimePkgType(e ast.Expr, want string) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != want {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "time"
}
