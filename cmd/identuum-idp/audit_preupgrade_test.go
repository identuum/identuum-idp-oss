package main

import (
	"strings"
	"testing"
)

// THE-OPERATOR-AUDIT (2026-09-01). Two invariants worth pinning:
//
//  1. READ-ONLY: every statement the audit may issue is a SELECT. An audit
//     that mutates is worse than no audit — the operator runs it against
//     production BEFORE upgrading.
//  2. SHAPE COMPLETENESS: every stored shape the guards now refuse is
//     flagged, each under the rule ID that refuses it. An audit that misses
//     a shape tells the operator "clean" while the upgrade will break that
//     row's updates — the lying-message class again, in a tool built to
//     prevent it.
//
// The evaluators are pure (rows in, findings out), so the proof needs no
// database; the SQL set is pinned as text.
//
// RULE: AUDIT-PREUPGRADE-1
func TestAuditPreupgrade_ReadOnlyAndFlagsEveryRefusedShape(t *testing.T) {
	// ── 1. READ-ONLY ──
	for name, q := range auditPreupgradeQueries {
		trimmed := strings.ToUpper(strings.TrimSpace(q))
		if !strings.HasPrefix(trimmed, "SELECT") {
			t.Errorf("audit query %q is not a SELECT — the audit must never mutate", name)
		}
		for _, verb := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "ALTER", "DROP", "CREATE"} {
			if strings.HasPrefix(trimmed, verb) {
				t.Errorf("audit query %q begins with %s", name, verb)
			}
		}
	}
	// Every audited entity must have a query — losing one silently shrinks
	// the sweep.
	for _, entity := range []string{"organizations", "users", "oauth_clients", "service_accounts", "org_roles", "api_resources", "scope_templates"} {
		if _, ok := auditPreupgradeQueries[entity]; !ok {
			t.Errorf("the audit lost its %s query — that entity is no longer swept", entity)
		}
	}

	// ── 2. SHAPE COMPLETENESS: one seeded bad row per shape, and the
	// finding must carry the rule ID that refuses it ──
	type want struct{ shape, rule string }
	assertFlags := func(t *testing.T, got []auditFinding, wants []want) {
		t.Helper()
		for _, w := range wants {
			found := false
			for _, f := range got {
				if strings.Contains(f.Shape, w.shape) {
					found = true
					if !strings.Contains(f.RuleID, w.rule) {
						t.Errorf("shape %q carries rule %q, want %q", f.Shape, f.RuleID, w.rule)
					}
					if f.Count < 1 {
						t.Errorf("shape %q flagged with count %d", f.Shape, f.Count)
					}
				}
			}
			if !found {
				t.Errorf("the audit MISSED the %q shape — it would report clean while the upgrade breaks that row", w.shape)
			}
		}
	}

	assertFlags(t, evaluateAuditOrgs([]auditOrgRow{
		{Domain: "lexus", Slug: "ok-slug", MaxSessions: 5, AuthPolicy: "mixed", APIAuthzPolicy: "strict"},
		{Domain: "LEXUS.COM.", Slug: "ok-slug", MaxSessions: 5, AuthPolicy: "mixed", APIAuthzPolicy: "strict"},
		{Domain: "acme.test", Slug: "Bad Slug!", MaxSessions: 5, AuthPolicy: "mixed", APIAuthzPolicy: "strict"},
		{Domain: "acme2.test", Slug: "ok-slug", MaxSessions: 500, M2MLimit: -1, AuthPolicy: "whenever", APIAuthzPolicy: "strict", ComplianceEmail: "not-an-email"},
	}), []want{
		{"DNS grammar", "ORG-DOMAIN-FORMAT-1"},
		{"un-normalized", "ORG-UPDATE-VALIDATION-1"},
		{"org_slug malformed", "ORG-DOMAIN-FORMAT-1"},
		{"max_sessions_per_user out of range", "ORG-UPDATE-VALIDATION-1"},
		{"m2m anomaly thresholds negative", "ORG-UPDATE-VALIDATION-1"},
		{"policy unlisted", "ORG-UPDATE-VALIDATION-1"},
		{"compliance contact email malformed", "ORG-UPDATE-VALIDATION-1"},
	})

	assertFlags(t, evaluateAuditUsers([]string{"not-an-email"}), []want{
		{"email fails RFC 5322", "USER-UPDATE-VALIDATION-1"},
	})

	assertFlags(t, evaluateAuditClients([]auditClientRow{
		{ClientID: "c1", Name: "   ", RedirectURIs: []string{"https://a.test/cb"}},
		{ClientID: "c2", Name: "ok", RedirectURIs: nil},
		{ClientID: "c3", Name: "ok", RedirectURIs: []string{"https://a.test/cb"}, Method: "none", SecretHash: "h"},
		{ClientID: "c4", Name: "ok", RedirectURIs: []string{"https://a.test/cb"}, IsPublic: true, SecretHash: "h"},
		{ClientID: "c5", Name: "ok", RedirectURIs: []string{"https://a.test/cb"}, IsPublic: true, HasSA: true},
		{ClientID: "c6", Name: "ok", RedirectURIs: []string{"https://a.test/cb"}, Method: "private_key_jwt", JWKSUri: "http://insecure.test/jwks"},
		// jwks material on a secret-based client: no named predicate — must
		// land in the completeness net, not vanish.
		{ClientID: "c7", Name: "ok", RedirectURIs: []string{"https://a.test/cb"}, Method: "client_secret_basic", SecretHash: "h", JWKS: `{"keys":[]}`},
	}), []want{
		{"name blank", "CLIENT-UPDATE-VALIDATION-1"},
		{"redirect_uris empty", "CLIENT-UPDATE-VALIDATION-1"},
		{"confidential client on method none", "CLIENT-UPDATE-DOCUMENT-1"},
		{"public client holding a secret hash", "CLIENT-CREATE-VALIDATION-1"},
		{"public client bound to a service account", "CLIENT-CREATE-VALIDATION-1"},
		{"non-https jwks_uri", "CLIENT-UPDATE-DOCUMENT-1"},
		{"other document violations", "CLIENT-UPDATE-DOCUMENT-1"},
	})

	assertFlags(t, evaluateAuditServiceAccounts([][2]string{
		{"   ", "org_user"},
		{"ok", "wizard"},
	}), []want{
		{"name blank", "SERVICE-ACCOUNT-UPDATE-BLANK-1"},
		{"role outside", "SERVICE-ACCOUNT-UPDATE-BLANK-1"},
	})

	assertFlags(t, evaluateAuditOrgRoles([]string{"   "}), []want{
		{"name blank", "ORG-ROLE-UPDATE-BLANK-1"},
	})

	assertFlags(t, evaluateAuditResources([]auditResourceRow{
		{Name: "   ", Audience: "https://a.test", TTL: 3600},
		{Name: "ok", Audience: "   ", TTL: 3600},
		{Name: "ok2", Audience: "https://b.test", TTL: 0},
		{Name: "ok3", Audience: "https://c.test", TTL: 3600, Scopes: []string{"system:root"}},
	}), []want{
		{"name blank", "REQUIRED-NAME-NOT-WHITESPACE-1"},
		{"audience blank", "REQUIRED-NAME-NOT-WHITESPACE-1"},
		{"token_ttl_secs not positive", "API-RESOURCE-REFUSAL-STATUS-1"},
		{"scope set refused", "API-RESOURCE-REFUSAL-STATUS-1"},
	})

	assertFlags(t, evaluateAuditTemplates([]auditTemplateRow{
		{Name: "   ", Scopes: []string{"read:x"}},
		{Name: "ok", Scopes: []string{"keys:steal"}},
	}), []want{
		{"name blank", "REQUIRED-NAME-NOT-WHITESPACE-1"},
		{"other template violations", "SCOPE-TEMPLATE-UPDATE-BLANK-1"},
	})

	// ── and CLEAN data must produce ZERO findings, so an audit that cried
	// wolf on healthy rows would not pass either ──
	clean := 0
	clean += len(evaluateAuditOrgs([]auditOrgRow{{Domain: "acme.test", Slug: "acme", MaxSessions: 5, AuthPolicy: "mixed", APIAuthzPolicy: "strict"}}))
	clean += len(evaluateAuditUsers([]string{"someone@example.com"}))
	clean += len(evaluateAuditClients([]auditClientRow{{ClientID: "c", Name: "App", RedirectURIs: []string{"https://a.test/cb"}, Method: "client_secret_basic", SecretHash: "h"}}))
	clean += len(evaluateAuditServiceAccounts([][2]string{{"ci", "org_user"}}))
	clean += len(evaluateAuditOrgRoles([]string{"Auditor"}))
	clean += len(evaluateAuditResources([]auditResourceRow{{Name: "API", Audience: "https://a.test", TTL: 3600, Scopes: []string{"read:x"}}}))
	clean += len(evaluateAuditTemplates([]auditTemplateRow{{Name: "Reader", Scopes: []string{"read:x"}}}))
	if clean != 0 {
		t.Errorf("clean fixtures produced %d findings — the audit cries wolf", clean)
	}
}
