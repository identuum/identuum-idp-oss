package mw

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// TestBearerRefSubjectIsBuiltFromSub pins the SOURCE of PrincipalRef.Subject in
// bearer.go: it must be the principal's Sub, and it must not be built from
// UserID.
//
// Why a structural pin on top of the behavioural ones: the behavioural teeth
// (bearer_subject_verbatim_test.go) hand BearerPrincipal a principal whose Sub
// and UserID differ, so they DO catch a straight revert. What they cannot catch
// is a future edit that reintroduces UserID as a fallback — e.g.
//
//	subject := principal.Sub
//	if subject == "" {
//	    subject = principal.UserID.String()   // <- the guess CONF-11 forbids
//	}
//
// because every one of those teeth supplies either a real Sub or asserts on the
// empty case only through the resolver, and a fallback keeps some of them green
// while silently restoring the uuid-shaped guess. The prohibition is on the
// TEXT, so it is pinned on the text.
//
// CONF-10's lesson applied: assert the VALUE, not that a key is present. A pin
// that only checked for a `Subject:` key stayed green through a mutation that
// disabled the feature entirely.
func TestBearerRefSubjectIsBuiltFromSub(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bearer.go", nil, 0)
	if err != nil {
		t.Fatalf("parse bearer.go: %v", err)
	}

	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		// oidc.PrincipalRef{...}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "PrincipalRef" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			id, ok := kv.Key.(*ast.Ident)
			if !ok || id.Name != "Subject" {
				continue
			}
			found = true

			var buf strings.Builder
			if err := printer.Fprint(&buf, fset, kv.Value); err != nil {
				t.Fatalf("print Subject value: %v", err)
			}
			expr := buf.String()

			if strings.Contains(expr, "UserID") {
				t.Errorf("bearer.go builds PrincipalRef.Subject from %s — Subject is contractually the `sub` claim VERBATIM (pkg/oidc/subject.go:31), and UserID is a different value: uuid.Nil for a non-uuid sub, overwritten by a `user_id` claim. A subject-keyed resolver would be asked about a different principal than userinfo asks about, for the same token (CONF-11).", expr)
			}
			if !strings.HasSuffix(expr, ".Sub") {
				t.Errorf("bearer.go builds PrincipalRef.Subject from %s, want the principal's .Sub — anything else is not the verbatim sub claim the seam contract requires (CONF-11)", expr)
			}
		}
		return true
	})

	if !found {
		t.Fatalf("no oidc.PrincipalRef composite literal with a Subject field found in bearer.go — this pin has drifted off its target and is no longer proving anything")
	}
}
