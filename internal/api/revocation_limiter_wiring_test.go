package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestRevocationRouteWiresLimiter pins that the production router actually
// PASSES a Limiter to RegisterRevocationRoutes.
//
// Why an AST pin rather than a behavioural one: the CONF-7 teeth in
// internal/handlers/revocation_ratelimit_test.go build their own engine and
// their own limiter, so they prove the handler mounts a limiter correctly and
// in the right order — but they say nothing about whether the RUNTIME hands it
// one. Deleting the `Limiter:` line here left every test in the repo green
// while production /revoke silently reverted to an unthrottled client_secret
// oracle. That mutation is exactly what this test exists to catch, and it was
// found by review of 9b63c72 rather than by the original teeth.
//
// The assertion is deliberately structural (does the call site set the field)
// rather than value-based: what rots is someone deleting or renaming the line
// during an unrelated refactor, not the constant behind it — that is already
// pinned by internal/runtime's default-config table.
func TestRevocationRouteWiresLimiter(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "router.go", nil, 0)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var (
		foundCall bool
		hasLimit  bool
	)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RegisterRevocationRoutes" {
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
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Limiter" {
					hasLimit = true
				}
			}
		}
		return true
	})

	if !foundCall {
		t.Fatalf("no RegisterRevocationRoutes call found in router.go — this pin has drifted off its target and is no longer proving anything")
	}
	if !hasLimit {
		t.Errorf("router.go calls RegisterRevocationRoutes WITHOUT a Limiter — /api/v1/oauth/revoke is an unthrottled client_secret oracle again (CONF-7)")
	}
}
