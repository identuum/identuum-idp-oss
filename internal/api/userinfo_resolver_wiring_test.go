package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestUserinfoRouteWiresSubjectResolver pins that the production router PASSES
// a SubjectResolver to RegisterUserinfoRoutes.
//
// Why an AST pin: the CONF-10 teeth in internal/handlers build their own deps,
// so they prove the handler applies the verdict correctly — but say nothing
// about whether the runtime hands it one. CONF-7 established that this gap is
// real, not theoretical: deleting a single wiring line in this file left every
// test in the repo green while the production endpoint silently lost its
// protection. Same shape here — without this pin, removing SubjectResolver
// would reopen the banned-user form-field hole with a fully green suite.
//
// Structural on purpose: what rots is the line being dropped, or the session
// lookup behind it being severed, in an unrelated refactor — not the resolver's
// behaviour (already pinned in internal/mw and internal/handlers).
//
// It asserts the VALUE, not just the key, and that is not gold-plating. Review
// of this commit mutated the argument to mw.NewSessionSubjectResolver(nil),
// which returns a nil resolver, which makes the handler's `!= nil` guard skip
// the gate — production hole fully reopened. Every test in the repo stayed
// green, INCLUDING an earlier version of this pin that only looked for the
// `SubjectResolver:` key. A key-presence assertion proves the field is
// mentioned, not that it is wired; only the argument makes it load-bearing.
func TestUserinfoRouteWiresSubjectResolver(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "router.go", nil, 0)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var foundCall bool
	var resolverVal ast.Expr
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RegisterUserinfoRoutes" {
			return true
		}
		foundCall = true
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "SubjectResolver" {
					resolverVal = kv.Value
				}
			}
		}
		return true
	})

	if !foundCall {
		t.Fatalf("no RegisterUserinfoRoutes call found in router.go — this pin has drifted off its target and is no longer proving anything")
	}
	if resolverVal == nil {
		t.Fatalf("router.go calls RegisterUserinfoRoutes WITHOUT a SubjectResolver — the access_token form-field door admits banned users again (CONF-10)")
	}

	// The value must be the single construction site, called with the real
	// session lookup. A nil argument yields a nil resolver and silently
	// disables the gate.
	ctor, ok := resolverVal.(*ast.CallExpr)
	if !ok {
		t.Fatalf("SubjectResolver is %T, want a call to mw.NewSessionSubjectResolver — CONF-10 keeps exactly one construction site", resolverVal)
	}
	ctorSel, ok := ctor.Fun.(*ast.SelectorExpr)
	if !ok || ctorSel.Sel.Name != "NewSessionSubjectResolver" {
		t.Fatalf("SubjectResolver is not built by mw.NewSessionSubjectResolver — a second construction site defeats the single-site guarantee")
	}
	if len(ctor.Args) != 1 {
		t.Fatalf("mw.NewSessionSubjectResolver called with %d args, want 1", len(ctor.Args))
	}

	arg := ctor.Args[0]
	if id, ok := arg.(*ast.Ident); ok && id.Name == "nil" {
		t.Fatalf("mw.NewSessionSubjectResolver(nil) — returns a nil resolver, so the handler skips the liveness gate entirely and the banned-user form-field hole is REOPEN, with no other test able to see it (CONF-10)")
	}
	lookup, ok := arg.(*ast.SelectorExpr)
	if !ok || lookup.Sel.Name != "SessionLookup" {
		t.Errorf("mw.NewSessionSubjectResolver argument is %T, want the resolved SessionLookup — without the real lookup there is no liveness verdict to apply (CONF-10)", arg)
	}
}
