package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// THE-ID-TOKEN-CLAIMS-PARITY (2026-09-04): the authorization_code grant mints a
// DERIVED session from the browser session and copies the authentication context
// onto it. It used to copy EffectiveACR() — the uplifted rung after a step-up —
// alongside the RAW Amr, which predates the uplift. The derived session then
// minted id_tokens saying acr=urn:identuum:loa:mfa with amr=["pwd"]: two claims
// in ONE token disagreeing about the same login, and disagreeing with what the
// parent session's id_token had already told the same relying party.
//
// This is an AST WIRING PIN and it asserts the VALUE, not the field name: the
// Amr field of the CreateUserSessionInput literal must be a call to
// EffectiveAMR, never the bare session.Amr selector. A behavioural test would
// need the whole grant (client auth, code exchange, session store); the defect
// is a one-token data-flow slip, and this catches exactly that slip at the site.
//
// RULE: AUTHCODE-DERIVED-AMR-EFFECTIVE-1
func TestAuthorizationCodeGrant_DerivedSessionCopiesEffectiveAMR(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "token.go", nil, 0)
	if err != nil {
		t.Fatalf("parse token.go: %v", err)
	}

	var acr, amr ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "CreateUserSessionInput" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Acr":
				acr = kv.Value
			case "Amr":
				amr = kv.Value
			}
		}
		return true
	})

	if acr == nil || amr == nil {
		t.Fatalf("no CreateUserSessionInput literal with both Acr and Amr found in token.go — the derived-session mint moved; re-point this pin")
	}

	callee := func(e ast.Expr) string {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		return sel.Sel.Name
	}

	if got := callee(acr); got != "EffectiveACR" {
		t.Errorf("derived session Acr is wired to %q, want a call to EffectiveACR", got)
	}
	// The one that regressed. A bare `session.Amr` selector is not a call, so
	// callee returns "" and this fails by name.
	if got := callee(amr); got != "EffectiveAMR" {
		t.Errorf("derived session Amr is wired to %q, want a call to EffectiveAMR — copying the RAW Amr next to an EffectiveACR gives the derived session a step-up rung with the pre-step-up methods, and its id_token then contradicts itself", got)
	}
}
