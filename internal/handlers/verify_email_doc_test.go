package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// V6-037 (testbook; judge ruling: keep 400): a used verification link answers
// 400 invalid_token, the one answer for every failure. The docs said
// "Idempotent ... returns 200". The route summary, the generated OpenAPI spec
// and the handler's doc comment must say single use, and not idempotent.
func TestVerifyEmail_DocsSaySingleUse(t *testing.T) {
	src, err := os.ReadFile("auth_lifecycle.go")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var summary string
	for _, line := range strings.Split(string(src), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), "// docgen:summary=Verify an email address"); ok {
			summary = "Verify an email address" + s
		}
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "auth_lifecycle.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var comment string
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "HandleVerifyEmail" && fn.Doc != nil {
			comment = fn.Doc.Text()
		}
	}
	for name, text := range map[string]string{"docgen summary": summary, "handler comment": comment} {
		if text == "" {
			t.Fatalf("the %s was not found", name)
		}
		if strings.Contains(strings.ToLower(text), "idempotent") || !strings.Contains(strings.ToLower(text), "single use") {
			t.Errorf("the %s must say single use and not idempotent: %q", name, text)
		}
	}
	if !strings.Contains(string(spec), summary) {
		t.Errorf("openapi.yaml does not carry the route summary; regenerate it with make api-docs")
	}
}
