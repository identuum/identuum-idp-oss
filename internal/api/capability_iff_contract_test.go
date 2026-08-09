package api

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// IDP OSS L3 capability iff-invariant contract harness.
//
// Landed by agent-a-20260766-idp-oss-l3-capability-iff-contract per
// the L3 gap recorded in
//
//	wiki/platform/workspace-stability-harness.md
//	  §"Repo coverage matrix" → identuum-idp-oss L3 column
//	  ("partial — internal/ access is the source of truth; no
//	   explicit cross-repo iff-invariant test inside OSS itself")
//
// Purpose: catch the regression class where the OSS componentHandler
// in internal/api/router.go declares a capability `true` but the
// route surface backing it has been renamed, unmounted, or moved.
// The existing tools/api-docgen/canonical_count_test.go (141 endpoints
// from agent-a-20260620 era) pins the TOTAL count but does not assert
// per-capability backing; this harness closes that hole at the
// source-text layer.
//
// Reference patterns:
//   - identuum-ag-oss/internal/server/capability_iff_contract_test.go
//     (agent-b-20260761 — the AG OSS L3 precedent we mirror)
//   - identuum-idp-ce/cmd/identuum-idp/account_settings_endpoint_contract_test.go
//     (agent-a-20260743 — the CE iff precedent inside the bigger
//     /account-settings surface family)
//
// SECURITY: source-text reflection only. No httptest, no real Gin
// engine at test time, no env reads, no secret material, no runtime
// state. Failure messages echo only mount-token strings (RegisterXRoutes
// function names + docgen:path annotations) — all of which are
// non-secret on the OSS production surface.

// repoRootIff returns the absolute path to the identuum-idp-oss
// module root. We use runtime.Caller so the test runs identically
// whether `go test` is invoked from the repo root or from internal/api/.
func repoRootIff(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs module root: %v", err)
	}
	return abs
}

// readIffSource returns the bytes of a repo-relative file. A missing
// file fails the test loudly.
func readIffSource(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(repoRootIff(t), rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// capBacking maps an IDP OSS capability flag name to one or more
// stable source-text tokens that back it. The tokens are deliberately
// chosen to be:
//
//   - Exported Go identifiers (Register*Routes), which any rename
//     surfaces in the test failure with high signal.
//   - OR docgen:path= annotations that the OSS docgen tool already
//     consumes, so the L1 canonical_count_test and this L3 contract
//     reference the same source-of-truth strings.
//
// `policyNote` documents the operator-facing rationale + is echoed
// in failure messages.
type capBacking struct {
	flag        string
	mountTokens []string
	src         string
	srcLabel    string
	policyNote  string
}

// TestCapabilityIff_TrueCapabilitiesBackedByRegisteredRoutes asserts
// that every capability advertised as `true` by the IDP OSS
// componentHandler is backed by at least one mount-token in source.
// A renamed registration function or a deleted handler fires here
// with a targeted message naming the missing token.
//
// Coverage today (17 true capabilities, all backed):
//
//	identity_provider            ← RegisterAuthSessionRoutes + /api/v1/auth/login
//	component_discovery          ← componentHandler in router.go (this endpoint itself)
//	license_status               ← componentHandler exposes "license" block
//	auth_provider_discovery      ← RegisterUsersRoutes (organization-lookup is co-located)
//	account_self_service         ← RegisterAccountLifecycleRoutes
//	user_sessions                ← RegisterSessionsRoutes
//	mfa                          ← /api/v1/auth/login/mfa in handlers (login MFA enrollment)
//	webauthn                     ← RegisterWebAuthnRoutes
//	authorization_server         ← RegisterAuthorizeRoutes
//	oauth_clients                ← RegisterClientsRoutes
//	api_resources                ← RegisterAPIResourcesRoutes
//	service_accounts             ← RegisterServiceAccountsRoutes
//	scope_templates              ← RegisterScopeTemplatesRoutes
//	org_roles                    ← RegisterRBACRoutes
//	protocol_settings            ← RegisterOrganizationProtocolSettingsRoutes
//	client_credentials           ← RegisterTokenRoutes (token endpoint handles client_credentials)
//	dynamic_client_registration  ← RegisterDCRRoutes
func TestCapabilityIff_TrueCapabilitiesBackedByRegisteredRoutes(t *testing.T) {
	router := readIffSource(t, "internal/api/router.go")
	authSessions := readIffSource(t, "internal/handlers/auth_sessions.go")
	authLifecycle := readIffSource(t, "internal/handlers/auth_lifecycle.go")
	sessions := readIffSource(t, "internal/handlers/sessions.go")
	webauthn := readIffSource(t, "internal/handlers/webauthn.go")
	authorize := readIffSource(t, "internal/handlers/authorize.go")
	clients := readIffSource(t, "internal/handlers/clients.go")
	audit := readIffSource(t, "internal/handlers/audit_events.go")
	apiResources := readIffSource(t, "internal/handlers/api_resources.go")
	serviceAccounts := readIffSource(t, "internal/handlers/service_accounts.go")
	scopeTemplates := readIffSource(t, "internal/handlers/scope_templates.go")
	rbac := readIffSource(t, "internal/handlers/rbac.go")
	protocolSettings := readIffSource(t, "internal/handlers/organization_protocol_settings.go")
	token := readIffSource(t, "internal/handlers/token.go")
	dcr := readIffSource(t, "internal/handlers/dcr.go")
	orgLookup := readIffSource(t, "internal/handlers/organization_lookup.go")

	backings := []capBacking{
		{
			flag:        "identity_provider",
			mountTokens: []string{`RegisterAuthSessionRoutes`, `router.POST("/api/v1/auth/login"`},
			src:         authSessions,
			srcLabel:    "internal/handlers/auth_sessions.go",
			policyNote:  "backed by RegisterAuthSessionRoutes + /api/v1/auth/login",
		},
		{
			flag:        "component_discovery",
			mountTokens: []string{`router.GET("/api/v1/component"`, `componentHandler(resolved)`},
			src:         router,
			srcLabel:    "internal/api/router.go",
			policyNote:  "backed by this endpoint itself (GET /api/v1/component)",
		},
		{
			flag:        "license_status",
			mountTokens: []string{`"license":`, `"product":         "identuum-idp-oss"`},
			src:         router,
			srcLabel:    "internal/api/router.go (componentHandler license block)",
			policyNote:  "backed by the license sub-object in the componentHandler response",
		},
		{
			flag:        "auth_provider_discovery",
			mountTokens: []string{`/api/v1/auth/organization-lookup`},
			src:         orgLookup,
			srcLabel:    "internal/handlers/organization_lookup.go",
			policyNote:  "backed by /api/v1/auth/organization-lookup (auth-provider discovery via org)",
		},
		{
			flag:        "account_self_service",
			mountTokens: []string{`RegisterAccountLifecycleRoutes`, `/api/v1/auth/verify-email`},
			src:         authLifecycle,
			srcLabel:    "internal/handlers/auth_lifecycle.go",
			policyNote:  "backed by RegisterAccountLifecycleRoutes (verify-email / password reset / claim)",
		},
		{
			flag:        "user_sessions",
			mountTokens: []string{`RegisterSessionsRoutes`, `/api/v1/sessions`},
			src:         sessions,
			srcLabel:    "internal/handlers/sessions.go",
			policyNote:  "backed by RegisterSessionsRoutes + /api/v1/sessions",
		},
		{
			flag:        "mfa",
			mountTokens: []string{`/api/v1/auth/login/mfa`, `/api/v1/auth/login/mfa/enroll/initiate`},
			src:         authSessions,
			srcLabel:    "internal/handlers/auth_sessions.go",
			policyNote:  "backed by login-flow MFA endpoints (challenge + enrollment)",
		},
		{
			flag:        "webauthn",
			mountTokens: []string{`RegisterWebAuthnRoutes`, `/api/v1/webauthn/register/begin`},
			src:         webauthn,
			srcLabel:    "internal/handlers/webauthn.go",
			policyNote:  "backed by RegisterWebAuthnRoutes + the register/begin endpoint",
		},
		{
			flag:        "authorization_server",
			mountTokens: []string{`RegisterAuthorizeRoutes`, `/api/v1/oauth/authorize`},
			src:         authorize,
			srcLabel:    "internal/handlers/authorize.go",
			policyNote:  "backed by RegisterAuthorizeRoutes + /api/v1/oauth/authorize",
		},
		{
			flag:        "oauth_clients",
			mountTokens: []string{`RegisterClientsRoutes`, `docgen:path=/api/v1/clients`},
			src:         clients,
			srcLabel:    "internal/handlers/clients.go",
			policyNote:  "backed by RegisterClientsRoutes + /api/v1/clients CRUD",
		},
		{
			flag:        "api_resources",
			mountTokens: []string{`RegisterAPIResourcesRoutes`},
			src:         apiResources,
			srcLabel:    "internal/handlers/api_resources.go",
			policyNote:  "backed by RegisterAPIResourcesRoutes",
		},
		{
			flag:        "service_accounts",
			mountTokens: []string{`RegisterServiceAccountsRoutes`},
			src:         serviceAccounts,
			srcLabel:    "internal/handlers/service_accounts.go",
			policyNote:  "backed by RegisterServiceAccountsRoutes",
		},
		{
			flag:        "scope_templates",
			mountTokens: []string{`RegisterScopeTemplatesRoutes`},
			src:         scopeTemplates,
			srcLabel:    "internal/handlers/scope_templates.go",
			policyNote:  "backed by RegisterScopeTemplatesRoutes",
		},
		{
			flag:        "org_roles",
			mountTokens: []string{`RegisterRBACRoutes`},
			src:         rbac,
			srcLabel:    "internal/handlers/rbac.go",
			policyNote:  "backed by RegisterRBACRoutes (RBAC implements org-roles surface)",
		},
		{
			flag:        "protocol_settings",
			mountTokens: []string{`RegisterOrganizationProtocolSettingsRoutes`},
			src:         protocolSettings,
			srcLabel:    "internal/handlers/organization_protocol_settings.go",
			policyNote:  "backed by RegisterOrganizationProtocolSettingsRoutes",
		},
		{
			flag:        "client_credentials",
			mountTokens: []string{`RegisterTokenRoutes`, `client_credentials`},
			src:         token,
			srcLabel:    "internal/handlers/token.go",
			policyNote:  "backed by RegisterTokenRoutes (token endpoint supports client_credentials grant)",
		},
		{
			flag:        "dynamic_client_registration",
			mountTokens: []string{`RegisterDCRRoutes`},
			src:         dcr,
			srcLabel:    "internal/handlers/dcr.go",
			policyNote:  "backed by RegisterDCRRoutes (RFC 7591)",
		},
		{
			flag:        "audit_log",
			mountTokens: []string{`RegisterAuditRoutes`},
			src:         audit,
			srcLabel:    "internal/handlers/audit_events.go",
			policyNote:  "backed by RegisterAuditRoutes — the L-2 plain persistent audit log read surface GET /api/v1/audit/events (the tamper-evident chain, anomaly detection and reporting stay CE)",
		},
	}

	for _, b := range backings {
		t.Run(b.flag, func(t *testing.T) {
			for _, tok := range b.mountTokens {
				if !strings.Contains(b.src, tok) {
					t.Errorf("capability %q claims true but backing token %q not found in %s (policy: %s)",
						b.flag, tok, b.srcLabel, b.policyNote)
				}
			}
		})
	}
}

// TestCapabilityIff_FalseCapabilitiesDocumentedPolicy asserts the
// policy stance for each capability advertised as `false` by the OSS
// componentHandler. Two policy classes:
//
//   - "absent-by-design": no production source backing exists, and
//     no source token should appear. audit_log, audit_chain, reporting,
//     anomaly_detection, observability are CE-tier surfaces; OSS
//     should NOT mount them.
//   - SCIM was formerly "conservative-false-by-policy" (shipped but
//     advertised false). It has been REMOVED from OSS entirely to close
//     a licensing leak (SCIM 2.0 is a paid CE feature — Professional and
//     above). It is now
//     absent-by-design: RegisterSCIMRoutes appears in no handler file,
//     and the component map literal retains `"scim": false`. See
//     docs/audit/changelog/scim-oss-leak-removal.md.
func TestCapabilityIff_FalseCapabilitiesDocumentedPolicy(t *testing.T) {
	router := readIffSource(t, "internal/api/router.go")

	// Absent-by-design false capabilities: no Register* function and
	// no /api/v1/<surface> docgen path should appear in any production
	// handler file. These are CE-tier surfaces that OSS does not ship.
	type absentCheck struct {
		flag           string
		forbiddenToken string
		policyNote     string
	}
	absent := []absentCheck{
		{"audit_chain", "RegisterAuditChainRoutes", "audit_chain is CE-tier"},
		{"reporting", "RegisterReportsRoutes", "reporting is CE-tier"},
		{"anomaly_detection", "RegisterAnomalyRoutes", "anomaly_detection is CE-tier"},
		{"observability", "RegisterObservabilityRoutes", "observability is CE-tier; OSS exposes /metrics + /health only"},
		{"scim", "RegisterSCIMRoutes", "scim is a paid CE feature (Professional and above); removed from OSS to close a licensing leak (docs/audit/changelog/scim-oss-leak-removal.md)"},
	}
	for _, a := range absent {
		t.Run(a.flag+"_absent_by_design", func(t *testing.T) {
			handlerDir := filepath.Join(repoRootIff(t), "internal", "handlers")
			entries, err := os.ReadDir(handlerDir)
			if err != nil {
				t.Fatalf("read handler dir: %v", err)
			}
			for _, e := range entries {
				if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
					continue
				}
				path := filepath.Join(handlerDir, e.Name())
				body, rerr := os.ReadFile(path)
				if rerr != nil {
					continue
				}
				if strings.Contains(string(body), a.forbiddenToken) {
					t.Errorf("capability %q is `false` (absent-by-design) but token %q appears in %s; "+
						"flip the capability + add explicit backing in the same slice (policy: %s)",
						a.flag, a.forbiddenToken, e.Name(), a.policyNote)
				}
			}
		})
	}

	// SCIM is absent-by-design (removed from OSS to close a licensing
	// leak — a paid CE feature, Professional and above). The absent-by-design loop above already
	// asserts RegisterSCIMRoutes appears in NO handler file. Here we pin
	// the RETAINED capability signal: the component map literal still
	// declares `"scim": false` (KEEP — UI + CE both rely on it).
	t.Run("scim_capability_stays_false", func(t *testing.T) {
		if !strings.Contains(router, `"scim":                        false`) {
			t.Errorf("component map literal for scim drifted away from `false`; OSS must continue to " +
				"advertise scim=false after the SCIM route removal (see scim-oss-leak-removal.md)")
		}
	})
}

// TestCapabilityIff_AllAdvertisedCapabilitiesCovered serves as a
// cross-check: it asserts that the static iff table above (the union
// of `true` backings + `false` documented policies) covers every
// capability key in the componentHandler literal. A new capability
// added to componentHandler without a corresponding row in either
// table fires here with a targeted "missing iff entry" message.
//
// The covered set is derived from the per-test `flag` strings above;
// we hard-code it here to keep the failure message high-signal.
func TestCapabilityIff_AllAdvertisedCapabilitiesCovered(t *testing.T) {
	router := readIffSource(t, "internal/api/router.go")

	covered := map[string]bool{
		// true capabilities (TestCapabilityIff_TrueCapabilitiesBackedByRegisteredRoutes)
		"identity_provider":           true,
		"component_discovery":         true,
		"license_status":              true,
		"auth_provider_discovery":     true,
		"account_self_service":        true,
		"user_sessions":               true,
		"mfa":                         true,
		"webauthn":                    true,
		"authorization_server":        true,
		"oauth_clients":               true,
		"api_resources":               true,
		"service_accounts":            true,
		"scope_templates":             true,
		"org_roles":                   true,
		"protocol_settings":           true,
		"client_credentials":          true,
		"dynamic_client_registration": true,
		// false capabilities (TestCapabilityIff_FalseCapabilitiesDocumentedPolicy)
		"scim":              true,
		"audit_log":         true,
		"audit_chain":       true,
		"reporting":         true,
		"anomaly_detection": true,
		"observability":     true,
	}

	// Extract every `"<key>":` token inside the componentHandler
	// capabilities literal. The capabilities block is delimited by
	// `"capabilities": gin.H{` and the closing `},` — we use a
	// targeted slice so unrelated `"key":` tokens elsewhere in
	// router.go (license fields, auth fields, etc.) are excluded.
	startTag := `"capabilities": gin.H{`
	startIdx := strings.Index(router, startTag)
	if startIdx < 0 {
		t.Fatal(`could not locate "capabilities": gin.H{ in internal/api/router.go`)
	}
	tail := router[startIdx+len(startTag):]
	endIdx := strings.Index(tail, `},`)
	if endIdx < 0 {
		t.Fatal("could not locate end of capabilities literal block")
	}
	block := tail[:endIdx]

	// Each line in `block` looks like:
	//   "capability_name":           true,
	// We extract the quoted key and check membership in `covered`.
	missing := []string{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			continue
		}
		key := line[1 : 1+end]
		if _, ok := covered[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("capabilities advertised by componentHandler with no matching iff-contract entry: %v\n"+
			"   → either add a `true`-row in TestCapabilityIff_TrueCapabilitiesBackedByRegisteredRoutes "+
			"OR a `false`-policy row in TestCapabilityIff_FalseCapabilitiesDocumentedPolicy in the SAME slice "+
			"that adds the capability key.", missing)
	}
}
