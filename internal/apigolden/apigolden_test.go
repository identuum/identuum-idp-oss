// Package apigolden pins the exported API of every public package under pkg/
// (OSS-SEAM-1, owner ruling w, 2026-10-08): the compatibility promise in
// docs/PUBLIC-API.md is only as good as the check that sees a change. The
// test prints each package's exported declarations — functions, methods on
// exported types, types with their exported fields, constants and variables —
// from the non-test sources, sorted, and compares the text with
// testdata/pkg.api. A change to the public surface is a deliberate edit of
// that file: regenerate it with IDENTUUM_UPDATE_API_GOLDEN=1 and review the
// diff as an API change.
package apigolden

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const golden = "testdata/pkg.api"

func TestPublicAPIMatchesTheGolden(t *testing.T) {
	got := publicAPI(t, filepath.Join("..", "..", "pkg"))
	if os.Getenv("IDENTUUM_UPDATE_API_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		inWant := map[string]bool{}
		for _, l := range wl {
			inWant[l] = true
		}
		inGot := map[string]bool{}
		for _, l := range gl {
			inGot[l] = true
			if !inWant[l] {
				t.Errorf("added to the public API:   %s", l)
			}
		}
		for _, l := range wl {
			if !inGot[l] {
				t.Errorf("removed from the public API: %s", l)
			}
		}
		t.Fatalf("the public API differs from %s; if the change is intended, regenerate it with IDENTUUM_UPDATE_API_GOLDEN=1", golden)
	}
}

// publicAPI renders the exported declarations of every package directory
// directly under root, one line per declaration, grouped by package.
func publicAPI(t *testing.T, root string) string {
	t.Helper()
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		lines := packageAPI(t, filepath.Join(root, d.Name()))
		out.WriteString("package pkg/" + d.Name() + "\n")
		for _, l := range lines {
			out.WriteString("  " + l + "\n")
		}
	}
	return out.String()
}

func packageAPI(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	render := func(n any) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() || (d.Recv != nil && !receiverExported(d.Recv)) {
					continue
				}
				fn := *d
				fn.Doc, fn.Body = nil, nil
				lines = append(lines, render(&fn))
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						ts := *s
						ts.Doc, ts.Comment = nil, nil
						ts.Type = exportedOnly(s.Type)
						lines = append(lines, "type "+render(&ts))
					case *ast.ValueSpec:
						for i, n := range s.Names {
							if !n.IsExported() {
								continue
							}
							line := d.Tok.String() + " " + n.Name
							if s.Type != nil {
								line += " " + render(s.Type)
							}
							if d.Tok == token.CONST && i < len(s.Values) {
								line += " = " + render(s.Values[i])
							}
							lines = append(lines, line)
						}
					}
				}
			}
		}
	}
	sort.Strings(lines)
	return lines
}

func receiverExported(recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) == 0 {
		return false
	}
	expr := recv.List[0].Type
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.Ident:
			return e.IsExported()
		default:
			return false
		}
	}
}

// exportedOnly keeps a struct's exported fields and an interface's exported
// methods; an unexported field is layout, not API, and is shown as a marker.
func exportedOnly(expr ast.Expr) ast.Expr {
	switch e := expr.(type) {
	case *ast.StructType:
		fields := &ast.FieldList{}
		hidden := false
		for _, f := range e.Fields.List {
			var names []*ast.Ident
			for _, n := range f.Names {
				if n.IsExported() {
					names = append(names, n)
				} else {
					hidden = true
				}
			}
			if len(f.Names) == 0 || len(names) > 0 {
				fields.List = append(fields.List, &ast.Field{Names: names, Type: f.Type, Tag: f.Tag})
			}
		}
		if hidden {
			fields.List = append(fields.List, &ast.Field{Names: []*ast.Ident{ast.NewIdent("_unexported")}, Type: ast.NewIdent("struct{}")})
		}
		return &ast.StructType{Fields: fields}
	case *ast.InterfaceType:
		methods := &ast.FieldList{}
		for _, m := range e.Methods.List {
			if len(m.Names) == 0 || m.Names[0].IsExported() {
				methods.List = append(methods.List, &ast.Field{Names: m.Names, Type: m.Type})
			}
		}
		return &ast.InterfaceType{Methods: methods}
	default:
		return expr
	}
}
