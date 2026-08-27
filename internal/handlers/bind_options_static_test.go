// bind_options_static_test.go — BIND-OPTIONS-GATE-1.
//
// THE-BIND-OPTIONS-GATE (2026-08-27). The axis nothing else watched:
// tessera compares the CLIENT to the server; this gate compares the
// WIRE to the SERVER'S OWN CAPABILITY. Twice this week a handler
// answered 200 while silently dropping fields its own service and
// repository fully support (users `active`, then FIVE organization
// fields) — the bind struct was the only layer that did not know.
//
// The check: every handler function that binds a request body AND feeds
// a *Options composite literal is analyzed statically. Each field of
// the Options TYPE is classified into one of three states:
//
//	FED             — set in the literal (or a later assignment to the
//	                  same variable). Wire-fed or consciously
//	                  server-set; either way the capability is owned.
//	BOUND-TO-REFUSE — not fed, but the bind struct carries a same-named
//	                  field: the handler binds it ONLY to refuse it
//	                  loudly before any write (tier). A naive wire-fed
//	                  check would count this as fed; it is not.
//	ABSENT          — not fed and not bound: the wire cannot see the
//	                  capability at all.
//
// BOUND-TO-REFUSE and ABSENT fail unless recorded in the justification
// ratchet below with the MATCHING state and a non-empty reason. The
// ratchet has stale teeth: a row whose field is now fed, whose claimed
// state no longer matches reality, or whose site vanished FAILS — the
// classification can never rot silently.
//
// WHAT THIS GATE CANNOT SEE (stated, not assumed): handler families
// that do not feed a *Options composite literal — service calls with
// positional arguments, request structs consumed directly, and
// query-param surfaces with no body bind (list/pagination). Options
// types are resolved from internal/service and internal/repository
// struct declarations only.
package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type optionsGap struct {
	State string // "bound-to-refuse" | "absent"
	Why   string
}

// bindOptionsJustified is the ratchet. Key:
// "<repo-relative-file>:<Func>.<OptionsType>.<Field>".
var bindOptionsJustified = map[string]optionsGap{
	// ── The two verdicts this gate was born from (THE-INERT-ORG-FIELDS) ──
	"internal/handlers/organizations.go:HandleUpdateOrganization.UpdateOrganizationOptions.Tier": {
		State: "bound-to-refuse",
		Why:   "tier is the LICENSING control — never client-settable, site_admin included; bound only so the handler can 400 tier_not_settable before any repository write (ORG-FIELDS-WIRE-1 pins the refusal).",
	},
	"internal/handlers/organizations.go:HandleUpdateOrganization.UpdateOrganizationOptions.ComplianceContactEmail": {
		State: "absent",
		Why:   "tenant-owned data on a site_admin-only endpoint: binding it would hand tenant data to infrastructure authority (AdminPermissionsModel). Gains a wire surface only with an org_admin-scoped settings path.",
	},

	// ── First-live-run adjudications (THE-BIND-OPTIONS-GATE item 3) ──

	// DCR (RFC 7591/7592) deliberately exposes only RFC-shaped client
	// metadata. allowed_audiences and service_account_id are Identuum
	// ADMIN-surface extensions (clients.go feeds both); letting a DCR
	// registrant attach a service account or grant itself audiences
	// would be privilege escalation through the self-registration door.
	"internal/handlers/dcr.go:HandleDCRRegister.RegisterClientOptions.AllowedAudiences": {
		State: "absent",
		Why:   "DCR is the RFC 7591 self-registration surface: audience grants are an admin decision (clients.go feeds this); a registrant granting itself audiences would be escalation.",
	},
	"internal/handlers/dcr.go:HandleDCRRegister.RegisterClientOptions.ServiceAccountID": {
		State: "absent",
		Why:   "DCR registrants must not bind themselves to service accounts — an admin-surface-only linkage (clients.go feeds this); self-service linkage would be escalation.",
	},
	"internal/handlers/dcr_management.go:HandleDCRManagementPut.UpdateClientOptions.AllowedAudiences": {
		State: "absent",
		Why:   "RFC 7592 management mirrors the 7591 posture: audience grants stay admin-only; the registration access token must not widen its own audience set.",
	},
	"internal/handlers/dcr_management.go:HandleDCRManagementPut.UpdateClientOptions.ServiceAccountID": {
		State: "absent",
		Why:   "RFC 7592 management mirrors the 7591 posture: service-account linkage stays admin-only.",
	},

	// Provenance must come from the authenticated principal, never the
	// body — client-supplied provenance is spoofable.
	"internal/handlers/keys.go:HandleGenerateSigningKey.GenerateKeyOptions.CreatedBy": {
		State: "absent",
		Why:   "operator provenance: the wire must never claim who created a key (spoofable). DEBT: the handler should derive CreatedBy from the authenticated principal — today it is left empty (~an eighth of a slice).",
	},

	// Password-policy knobs are SERVER inputs resolved by the caller,
	// never wire business — a client choosing the password policy that
	// validates its own payload would be self-attestation. On the admin
	// paths nobody resolves the org policy yet, so the documented safe
	// defaults apply (nil ⇒ strict complexity, 0 ⇒ floor 8) — strict in
	// the conservative direction. DEBT: plumb the target org's policy
	// in the three admin handlers (~a quarter slice).
	"internal/handlers/users.go:HandleCreateUser.CreateUserOptions.PasswordComplexityEnabled": {
		State: "absent",
		Why:   "server-resolved org policy, never wire-settable (self-attested password policy). Unplumbed on the admin path: safe default = strict. DEBT to plumb org lookup.",
	},
	"internal/handlers/users.go:HandleCreateUser.CreateUserOptions.MinPasswordLength": {
		State: "absent",
		Why:   "server-resolved policy floor, never wire-settable. Unplumbed on the admin path: safe default = 8. DEBT to plumb org lookup.",
	},
	"internal/handlers/users.go:HandleUpdateUser.UpdateUserOptions.PasswordComplexityEnabled": {
		State: "absent",
		Why:   "server-resolved org policy, never wire-settable. Unplumbed on the admin password-change path: safe default = strict. DEBT to plumb org lookup.",
	},
	"internal/handlers/users.go:HandleUpdateUser.UpdateUserOptions.MinPasswordLength": {
		State: "absent",
		Why:   "server-resolved policy floor, never wire-settable. Unplumbed on the admin password-change path: safe default = 8. DEBT to plumb org lookup.",
	},
	"internal/handlers/user_bulk_create.go:HandleBulkCreateUsers.CreateUserOptions.PasswordComplexityEnabled": {
		State: "absent",
		Why:   "server-resolved org policy, never wire-settable. Bulk create inherits the same unplumbed-org-policy DEBT as single create; safe default = strict.",
	},
	"internal/handlers/user_bulk_create.go:HandleBulkCreateUsers.CreateUserOptions.MinPasswordLength": {
		State: "absent",
		Why:   "server-resolved policy floor, never wire-settable. Bulk create inherits the same DEBT; safe default = 8.",
	},
}

// RULE: BIND-OPTIONS-GATE-1
func TestBindStructs_FeedTheirOptionsCapability(t *testing.T) {
	root := findOSSRoot(t)

	// 1. Index every `type XxxOptions struct` in the two capability
	// packages: type name -> exported field names.
	optionsIndex := map[string][]string{}
	for _, dir := range []string{"internal/service", "internal/repository"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, filepath.Join(root, dir, e.Name()), nil, 0)
			if perr != nil {
				t.Fatalf("parse %s/%s: %v", dir, e.Name(), perr)
			}
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, spec := range gd.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !strings.HasSuffix(ts.Name.Name, "Options") {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue // aliases resolve through their target's own decl
					}
					var fields []string
					for _, fl := range st.Fields.List {
						for _, n := range fl.Names {
							if n.IsExported() {
								fields = append(fields, n.Name)
							}
						}
					}
					if _, dup := optionsIndex[ts.Name.Name]; !dup {
						optionsIndex[ts.Name.Name] = fields
					}
				}
			}
		}
	}
	if len(optionsIndex) == 0 {
		t.Fatal("no Options types indexed — the capability packages moved?")
	}

	// 2. Walk the handler package: functions that BIND a body and FEED
	// an indexed Options literal.
	type siteHit struct {
		key    string // ratchet key
		state  string
		detail string
	}
	var hits []siteHit
	pairSites := 0

	hdir := filepath.Join(root, "internal", "handlers")
	entries, err := os.ReadDir(hdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(hdir, e.Name())
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		rel := filepath.ToSlash(filepath.Join("internal", "handlers", e.Name()))

		// Named local struct types (bind targets declared as named types).
		named := map[string]*ast.StructType{}
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok {
				for _, spec := range gd.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						if st, ok := ts.Type.(*ast.StructType); ok {
							named[ts.Name.Name] = st
						}
					}
				}
			}
		}

		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			// (a) bind vars: local structs actually passed to a body bind.
			local := map[string]*ast.StructType{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if ds, ok := n.(*ast.DeclStmt); ok {
					if gd, ok := ds.Decl.(*ast.GenDecl); ok {
						for _, spec := range gd.Specs {
							if vs, ok := spec.(*ast.ValueSpec); ok {
								var st *ast.StructType
								switch typ := vs.Type.(type) {
								case *ast.StructType:
									st = typ
								case *ast.Ident:
									st = named[typ.Name]
								}
								if st != nil {
									for _, name := range vs.Names {
										local[name.Name] = st
									}
								}
							}
						}
					}
				}
				return true
			})
			bindVars := map[string]*ast.StructType{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "ShouldBindJSON", "BindJSON", "ShouldBindBodyWith":
				default:
					return true
				}
				for _, arg := range call.Args {
					if un, ok := arg.(*ast.UnaryExpr); ok && un.Op == token.AND {
						if id, ok := un.X.(*ast.Ident); ok && local[id.Name] != nil {
							bindVars[id.Name] = local[id.Name]
						}
					}
				}
				return true
			})
			if len(bindVars) == 0 {
				continue // no body bind — out of this gate's frame (stated in the header)
			}

			// (b) Options literals + the variables they are assigned to.
			type litInfo struct {
				typeName string
				set      map[string]bool
			}
			lits := []*litInfo{}
			litByVar := map[string]*litInfo{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				var tname string
				switch typ := cl.Type.(type) {
				case *ast.SelectorExpr:
					tname = typ.Sel.Name
				case *ast.Ident:
					tname = typ.Name
				}
				if !strings.HasSuffix(tname, "Options") {
					return true
				}
				if _, indexed := optionsIndex[tname]; !indexed {
					return true
				}
				li := &litInfo{typeName: tname, set: map[string]bool{}}
				for _, el := range cl.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok {
							li.set[k.Name] = true
						}
					}
				}
				lits = append(lits, li)
				return true
			})
			if len(lits) == 0 {
				continue
			}
			// Literal assigned to a var (opts := T{...}) → later
			// `opts.Field = ...` assignments also feed it.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					return true
				}
				for i, rh := range as.Rhs {
					cl, ok := rh.(*ast.CompositeLit)
					if !ok {
						continue
					}
					var tname string
					switch typ := cl.Type.(type) {
					case *ast.SelectorExpr:
						tname = typ.Sel.Name
					case *ast.Ident:
						tname = typ.Name
					}
					if _, indexed := optionsIndex[tname]; !indexed || !strings.HasSuffix(tname, "Options") {
						continue
					}
					if id, ok := as.Lhs[i].(*ast.Ident); ok {
						for _, li := range lits {
							if li.typeName == tname {
								litByVar[id.Name] = li
							}
						}
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lh := range as.Lhs {
					if sel, ok := lh.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok {
							if li := litByVar[id.Name]; li != nil {
								li.set[sel.Sel.Name] = true
							}
						}
					}
				}
				return true
			})

			// (c) classify every Options field per literal.
			bindFieldNames := map[string]bool{}
			for _, st := range bindVars {
				for _, fl := range st.Fields.List {
					for _, n := range fl.Names {
						bindFieldNames[n.Name] = true
					}
				}
			}
			for _, li := range lits {
				pairSites++
				for _, field := range optionsIndex[li.typeName] {
					if li.set[field] {
						continue // FED — capability owned
					}
					state := "absent"
					if bindFieldNames[field] {
						state = "bound-to-refuse"
					}
					key := rel + ":" + fn.Name.Name + "." + li.typeName + "." + field
					hits = append(hits, siteHit{key: key, state: state,
						detail: fmt.Sprintf("%s [%s]", key, state)})
				}
			}
		}
	}
	if pairSites == 0 {
		t.Fatal("no bind→Options pair sites found — the handler layer moved?")
	}

	// 3. Ratchet: every gap justified with the MATCHING state; every
	// ratchet row still real.
	seen := map[string]string{}
	var fails []string
	for _, h := range hits {
		seen[h.key] = h.state
		row, ok := bindOptionsJustified[h.key]
		if !ok {
			fails = append(fails, "WIRE CANNOT REACH SERVER CAPABILITY: "+h.detail+
				" — feed it from the bind struct, refuse it loudly, or record the deliberate gap in bindOptionsJustified")
			continue
		}
		if row.State != h.state {
			fails = append(fails, fmt.Sprintf("STALE STATE for %s: ratchet says %q, code says %q — re-adjudicate", h.key, row.State, h.state))
		}
		if strings.TrimSpace(row.Why) == "" {
			fails = append(fails, "EMPTY justification for "+h.key)
		}
	}
	for key := range bindOptionsJustified {
		if _, ok := seen[key]; !ok {
			fails = append(fails, "STALE ratchet row (field now fed, renamed, or site gone): "+key)
		}
	}
	sort.Strings(fails)
	for _, f := range fails {
		t.Error(f)
	}
	t.Logf("EVIDENCE bind-options gate: %d Options types indexed, %d bind→Options pair sites, %d gap(s) all adjudicated", len(optionsIndex), pairSites, len(hits))
}
