package extension_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

// OSS-SEAM-4 proof 3: code outside the module holds a Decision but cannot
// build one — a literal that sets a field does not compile, and the zero
// Decision names no operation.
func TestDecision_OutsideCodeCannotBuildOne(t *testing.T) {
	if !(extension.Decision{}).IsZero() {
		t.Fatal("the zero Decision must report IsZero")
	}
	const fixture = `package outside

import "github.com/identuum/identuum-idp-oss/pkg/extension"

var D = extension.Decision{operation: "api_resource.create", tenant: "t"}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "outside.go", fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	var errs []string
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(e error) { errs = append(errs, e.Error()) }}
	_, _ = conf.Check("example.test/outside", fset, []*ast.File{f}, nil)
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "unexported field operation") || !strings.Contains(joined, "unexported field tenant") {
		t.Fatalf("a literal setting Decision fields from outside compiled, or failed for another reason: %q", joined)
	}
	if strings.Contains(joined, "could not import") {
		t.Fatalf("the fixture could not load pkg/extension: %q", joined)
	}
	t.Logf("refused as it must be: %s", joined)
}

// Ruling aa: 403 for restricted and license_required, 409 for
// quota_exceeded; never 429.
func TestDenial_Status(t *testing.T) {
	for code, want := range map[extension.Code]int{
		extension.Restricted: 403, extension.LicenseRequired: 403, extension.QuotaExceeded: 409,
	} {
		if got := (&extension.Denial{Code: code}).Status(); got != want {
			t.Errorf("%s answers %d; want %d", code, got, want)
		}
	}
}
