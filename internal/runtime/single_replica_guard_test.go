package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// P3-3: OSS keeps security state IN PROCESS — WebAuthn ceremonies
// (internal/repository/inmemory_webauthn_session_repository.go) and the
// rate-limit token buckets (internal/mw/rate_limit.go). Both are correct for a
// SINGLE replica and silently wrong across several: a ceremony started on one
// replica cannot complete on another, and per-IP limits divide by the replica
// count.
//
// The only thing standing between that and a real deployment is the A-2a
// single-replica instance lease, acquired here in Start. THAT is what makes
// P3-3 a documented constraint rather than a live hole — so if the lease is
// ever removed, refactored away, or made unconditional, the in-memory stores
// become a distributed-correctness bug with nothing announcing it.
//
// This pins the lease to the serving path by NAME. It is deliberately a
// structural assertion rather than a behavioural one: booting a Runtime needs a
// live database, and a guard that only runs under integration tags is a guard
// that does not run.
func TestP3_3_SingleReplicaLeaseIsWiredIntoStart(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "runtime.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing runtime.go: %v", err)
	}

	var start *ast.FuncDecl
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Start" && fn.Recv != nil {
			start = fn
			break
		}
	}
	// CONTROL: Start must exist, or every assertion below is vacuous.
	if start == nil {
		t.Fatal("CONTROL FAILED: (*Runtime).Start not found in runtime.go; this test proves nothing")
	}

	var body strings.Builder
	ast.Inspect(start, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			body.WriteString(id.Name)
			body.WriteByte(' ')
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			body.WriteString(sel.Sel.Name)
			body.WriteByte(' ')
		}
		return true
	})
	src := body.String()

	for _, want := range []string{"NewCoordinator", "Acquire"} {
		if !strings.Contains(src, want) {
			t.Errorf("P3-3: (*Runtime).Start no longer references %q. The single-replica lease is "+
				"the ONLY thing bounding OSS's in-process security state — in-memory WebAuthn "+
				"ceremonies and per-process rate-limit buckets. Removing it turns both into "+
				"distributed-correctness bugs with nothing announcing the change. If OSS is "+
				"intentionally going multi-replica, those two stores must move first and the P3-3 "+
				"row must be re-ruled", want)
		}
	}
}
