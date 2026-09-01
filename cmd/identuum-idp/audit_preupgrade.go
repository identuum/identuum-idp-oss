package main

// audit_preupgrade.go — THE-OPERATOR-AUDIT (2026-09-01).
//
// `identuum-idp audit-preupgrade <database-url>` is the READ-ONLY pre-upgrade
// sweep for rows that the validation arc's guards now refuse. The guards were
// added service-side; the database never enforced several of these shapes, so
// a deployment that wrote rows through an older binary can hold data that a
// NEW binary refuses — and on the full-document entities (clients,
// api-resources, scope-templates) that refusal fires on ANY update to the
// row, not just on re-supplying the bad field.
//
// The audit reuses THE SAME domain validators the guards run — no second
// grammar — and every SQL statement it issues is a SELECT (pinned by
// AUDIT-PREUPGRADE-1). It mutates nothing.
//
// Exit codes: 0 = clean; 1 = findings exist; 2 = usage, configuration, or
// database error (could not audit ≠ audited clean).

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// auditFinding is one nonzero shape count.
type auditFinding struct {
	Entity string
	Shape  string
	RuleID string
	Impact string // auditImpactCritical or auditImpactAdvisory
	Count  int
}

const (
	// The full-document entities validate the WHOLE row on update, so a
	// stored hit makes any update to that row fail.
	auditImpactCritical = "CRITICAL: any update to this row now fails"
	// The per-field entities validate only supplied values, so a stored hit
	// fails only when that field is re-supplied.
	auditImpactAdvisory = "advisory: fails only when the field is re-supplied"
)

// auditPreupgradeQueries is the COMPLETE set of SQL this audit may run.
// AUDIT-PREUPGRADE-1 pins that every entry is a SELECT; loadAuditRows
// additionally refuses at runtime to execute anything else.
var auditPreupgradeQueries = map[string]string{
	"organizations":    `SELECT domain, org_slug, max_sessions_per_user, m2m_anomaly_limit, m2m_anomaly_window_seconds, auth_policy, api_authorization_policy, coalesce(compliance_contact_email,'') FROM organizations`,
	"users":            `SELECT email FROM users WHERE deleted_at IS NULL`,
	"oauth_clients":    `SELECT client_id, name, coalesce(redirect_uris,'{}'), coalesce(scope,''), is_public, coalesce(client_secret_hash,''), service_account_id IS NOT NULL, coalesce(token_endpoint_auth_method,''), coalesce(token_endpoint_auth_signing_alg,''), coalesce(jwks_uri,''), coalesce(jwks,'') FROM oauth_clients WHERE deleted_at IS NULL`,
	"service_accounts": `SELECT name, role FROM service_accounts WHERE deleted_at IS NULL`,
	"org_roles":        `SELECT name FROM org_roles`,
	"api_resources":    `SELECT r.id, r.name, r.audience, r.token_ttl_secs, coalesce(array_agg(s.name) FILTER (WHERE s.name IS NOT NULL), '{}') FROM api_resources r LEFT JOIN api_resource_scopes s ON s.resource_id = r.id GROUP BY r.id, r.name, r.audience, r.token_ttl_secs`,
	"scope_templates":  `SELECT name, coalesce(scopes,'{}') FROM scope_templates`,
}

type auditOrgRow struct {
	Domain, Slug, AuthPolicy, APIAuthzPolicy, ComplianceEmail string
	MaxSessions, M2MLimit, M2MWindow                          int
}

type auditClientRow struct {
	ClientID, Name, Scope, SecretHash, Method, Alg, JWKSUri, JWKS string
	RedirectURIs                                                  []string
	IsPublic, HasSA                                               bool
}

type auditResourceRow struct {
	Name, Audience string
	TTL            int
	Scopes         []string
}

type auditTemplateRow struct {
	Name   string
	Scopes []string
}

// evaluateAuditOrgs applies the org guards' own validators to stored rows.
// Per-field entity: advisory.
func evaluateAuditOrgs(rows []auditOrgRow) []auditFinding {
	var grammar, unnormalized, slug, maxSess, m2m, policy, email int
	for _, r := range rows {
		if domain.ValidateDomainFormat(r.Domain) != nil {
			grammar++
		} else if r.Domain != domain.NormalizeDomain(r.Domain) {
			unnormalized++
		}
		if domain.ValidateOrganizationSlug(r.Slug) != nil {
			slug++
		}
		if domain.ValidateMaxSessionsPerUser(r.MaxSessions) != nil {
			maxSess++
		}
		if domain.ValidateM2MAnomalyLimit(r.M2MLimit) != nil || domain.ValidateM2MAnomalyWindowSeconds(r.M2MWindow) != nil {
			m2m++
		}
		// api_authorization_policy is compared case-insensitively on purpose:
		// the domain constant is "STRICT" while the DB column DEFAULT is
		// lowercase 'strict' — a raw-column comparison would flag every
		// default-valued organization. The clean-fixture half of
		// AUDIT-PREUPGRADE-1 caught exactly that during this audit's build.
		if domain.ValidateAuthPolicyValue(r.AuthPolicy) != nil || domain.ValidateAPIAuthorizationPolicyValue(strings.ToUpper(r.APIAuthzPolicy)) != nil {
			policy++
		}
		if domain.ValidateComplianceContactEmail(r.ComplianceEmail) != nil {
			email++
		}
	}
	return nonzero(
		auditFinding{"organizations", "domain fails the DNS grammar (e.g. a bare label)", "ORG-DOMAIN-FORMAT-1 / ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, grammar},
		auditFinding{"organizations", "domain stored un-normalized (case / trailing dot)", "ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, unnormalized},
		auditFinding{"organizations", "org_slug malformed", "ORG-DOMAIN-FORMAT-1", auditImpactAdvisory, slug},
		auditFinding{"organizations", "max_sessions_per_user out of range", "ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, maxSess},
		auditFinding{"organizations", "m2m anomaly thresholds negative", "ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, m2m},
		auditFinding{"organizations", "auth/api-authorization policy unlisted", "ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, policy},
		auditFinding{"organizations", "compliance contact email malformed", "ORG-UPDATE-VALIDATION-1", auditImpactAdvisory, email},
	)
}

// evaluateAuditUsers is belt-and-suspenders: the users table carries a CHECK
// constraint and a role ENUM, so hits here indicate schema drift.
func evaluateAuditUsers(emails []string) []auditFinding {
	var bad int
	for _, e := range emails {
		if domain.ValidateUserEmail(e) != nil {
			bad++
		}
	}
	return nonzero(auditFinding{"users", "email fails RFC 5322 parsing", "USER-UPDATE-VALIDATION-1", auditImpactAdvisory, bad})
}

// evaluateAuditClients: full-document entity — every hit is CRITICAL because
// UpdateClient now runs Client.Validate on the whole updated document.
func evaluateAuditClients(rows []auditClientRow) []auditFinding {
	var blankName, emptyRedirects, confNone, pubSecret, pubSA, pkjHTTP, otherDoc int
	for _, r := range rows {
		named := false
		if strings.TrimSpace(r.Name) == "" {
			blankName++
			named = true
		}
		if len(r.RedirectURIs) == 0 {
			emptyRedirects++
			named = true
		}
		if !r.IsPublic && r.Method == "none" {
			confNone++
			named = true
		}
		if r.IsPublic && r.SecretHash != "" {
			pubSecret++
			named = true
		}
		if r.IsPublic && r.HasSA {
			pubSA++
			named = true
		}
		c := domain.Client{
			ClientID:                    r.ClientID,
			Name:                        r.Name,
			RedirectURIs:                r.RedirectURIs,
			Scope:                       r.Scope,
			IsPublic:                    r.IsPublic,
			ClientSecretHash:            r.SecretHash,
			TokenEndpointAuthMethod:     r.Method,
			TokenEndpointAuthSigningAlg: r.Alg,
			JWKSUri:                     r.JWKSUri,
			JWKS:                        r.JWKS,
		}
		if r.HasSA {
			said := uuid.New() // presence is what Validate checks, not the value
			c.ServiceAccountID = &said
		}
		if c.EffectiveAuthMethod() == "private_key_jwt" {
			if u := strings.TrimSpace(r.JWKSUri); u != "" {
				if parsed, err := url.Parse(u); err != nil || parsed.Scheme != "https" {
					pkjHTTP++
					named = true
				}
			}
		}
		// COMPLETENESS NET: any row the document validator refuses that no
		// named shape above explains. Guarantees the audit cannot silently
		// under-report relative to the guard it fronts for.
		if err := c.Validate(); err != nil && !named {
			otherDoc++
		}
	}
	return nonzero(
		auditFinding{"oauth_clients", "name blank or whitespace-only", "CLIENT-UPDATE-VALIDATION-1", auditImpactCritical, blankName},
		auditFinding{"oauth_clients", "redirect_uris empty", "CLIENT-UPDATE-VALIDATION-1", auditImpactCritical, emptyRedirects},
		auditFinding{"oauth_clients", "confidential client on method none", "CLIENT-UPDATE-DOCUMENT-1", auditImpactCritical, confNone},
		auditFinding{"oauth_clients", "public client holding a secret hash", "CLIENT-CREATE-VALIDATION-1", auditImpactCritical, pubSecret},
		auditFinding{"oauth_clients", "public client bound to a service account", "CLIENT-CREATE-VALIDATION-1", auditImpactCritical, pubSA},
		auditFinding{"oauth_clients", "private_key_jwt with a non-https jwks_uri", "CLIENT-UPDATE-DOCUMENT-1", auditImpactCritical, pkjHTTP},
		auditFinding{"oauth_clients", "other document violations (Client.Validate)", "CLIENT-UPDATE-DOCUMENT-1", auditImpactCritical, otherDoc},
	)
}

func evaluateAuditServiceAccounts(rows [][2]string) []auditFinding {
	var wsName, badRole int
	for _, r := range rows {
		if strings.TrimSpace(r[0]) == "" {
			wsName++
		}
		if !domain.IsAllowedSARole(domain.UserRole(r[1])) {
			badRole++
		}
	}
	return nonzero(
		auditFinding{"service_accounts", "name blank or whitespace-only", "SERVICE-ACCOUNT-UPDATE-BLANK-1", auditImpactAdvisory, wsName},
		auditFinding{"service_accounts", "role outside the allowed set", "SERVICE-ACCOUNT-UPDATE-BLANK-1", auditImpactAdvisory, badRole},
	)
}

func evaluateAuditOrgRoles(names []string) []auditFinding {
	var wsName int
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			wsName++
		}
	}
	return nonzero(auditFinding{"org_roles", "name blank or whitespace-only", "ORG-ROLE-UPDATE-BLANK-1", auditImpactAdvisory, wsName})
}

// evaluateAuditResources: full-document on update — CRITICAL.
func evaluateAuditResources(rows []auditResourceRow) []auditFinding {
	var wsName, wsAudience, badTTL, badScopes int
	for _, r := range rows {
		if strings.TrimSpace(r.Name) == "" {
			wsName++
		}
		if strings.TrimSpace(r.Audience) == "" {
			wsAudience++
		}
		if r.TTL <= 0 {
			badTTL++
		}
		scopes := make([]domain.APIScope, 0, len(r.Scopes))
		for _, s := range r.Scopes {
			scopes = append(scopes, domain.APIScope{Name: s})
		}
		if domain.ValidateAPIScopes(scopes) != nil {
			badScopes++
		}
	}
	return nonzero(
		auditFinding{"api_resources", "name blank or whitespace-only", "REQUIRED-NAME-NOT-WHITESPACE-1", auditImpactCritical, wsName},
		auditFinding{"api_resources", "audience blank or whitespace-only", "REQUIRED-NAME-NOT-WHITESPACE-1", auditImpactCritical, wsAudience},
		auditFinding{"api_resources", "token_ttl_secs not positive", "API-RESOURCE-REFUSAL-STATUS-1", auditImpactCritical, badTTL},
		auditFinding{"api_resources", "scope set refused (reserved prefix / whitespace)", "API-RESOURCE-REFUSAL-STATUS-1", auditImpactCritical, badScopes},
	)
}

// evaluateAuditTemplates: full-document on update — CRITICAL.
func evaluateAuditTemplates(rows []auditTemplateRow) []auditFinding {
	var wsName, other int
	for _, r := range rows {
		named := false
		if strings.TrimSpace(r.Name) == "" {
			wsName++
			named = true
		}
		tpl := domain.ScopeTemplate{Name: r.Name, Scopes: r.Scopes}
		if err := tpl.Validate(); err != nil && !named {
			other++ // over-long name, empty scope list, reserved/whitespace scope
		}
	}
	return nonzero(
		auditFinding{"scope_templates", "name blank or whitespace-only", "REQUIRED-NAME-NOT-WHITESPACE-1", auditImpactCritical, wsName},
		auditFinding{"scope_templates", "other template violations (ScopeTemplate.Validate)", "SCOPE-TEMPLATE-UPDATE-BLANK-1", auditImpactCritical, other},
	)
}

func nonzero(all ...auditFinding) []auditFinding {
	out := make([]auditFinding, 0, len(all))
	for _, f := range all {
		if f.Count > 0 {
			out = append(out, f)
		}
	}
	return out
}

// runAuditPreupgrade connects, sweeps, prints, and exits per the contract in
// the file header. SELECT-only is enforced both here and by the pin test.
func runAuditPreupgrade(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	for name, q := range auditPreupgradeQueries {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SELECT") {
			fmt.Fprintf(stderr, "identuum-idp: audit-preupgrade: refusing to run non-SELECT query %q\n", name)
			return 2
		}
	}
	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: open pool failed:", redactURL(err, databaseURL))
		return 2
	}
	defer pool.Close()

	var findings []auditFinding

	var orgs []auditOrgRow
	rows, err := pool.Query(ctx, auditPreupgradeQueries["organizations"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: organizations:", err)
		return 2
	}
	for rows.Next() {
		var r auditOrgRow
		if err := rows.Scan(&r.Domain, &r.Slug, &r.MaxSessions, &r.M2MLimit, &r.M2MWindow, &r.AuthPolicy, &r.APIAuthzPolicy, &r.ComplianceEmail); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: organizations scan:", err)
			return 2
		}
		orgs = append(orgs, r)
	}
	rows.Close()
	findings = append(findings, evaluateAuditOrgs(orgs)...)

	var emails []string
	rows, err = pool.Query(ctx, auditPreupgradeQueries["users"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: users:", err)
		return 2
	}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: users scan:", err)
			return 2
		}
		emails = append(emails, e)
	}
	rows.Close()
	findings = append(findings, evaluateAuditUsers(emails)...)

	var clients []auditClientRow
	rows, err = pool.Query(ctx, auditPreupgradeQueries["oauth_clients"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: oauth_clients:", err)
		return 2
	}
	for rows.Next() {
		var r auditClientRow
		if err := rows.Scan(&r.ClientID, &r.Name, &r.RedirectURIs, &r.Scope, &r.IsPublic, &r.SecretHash, &r.HasSA, &r.Method, &r.Alg, &r.JWKSUri, &r.JWKS); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: oauth_clients scan:", err)
			return 2
		}
		clients = append(clients, r)
	}
	rows.Close()
	findings = append(findings, evaluateAuditClients(clients)...)

	var sas [][2]string
	rows, err = pool.Query(ctx, auditPreupgradeQueries["service_accounts"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: service_accounts:", err)
		return 2
	}
	for rows.Next() {
		var name, role string
		if err := rows.Scan(&name, &role); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: service_accounts scan:", err)
			return 2
		}
		sas = append(sas, [2]string{name, role})
	}
	rows.Close()
	findings = append(findings, evaluateAuditServiceAccounts(sas)...)

	var roleNames []string
	rows, err = pool.Query(ctx, auditPreupgradeQueries["org_roles"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: org_roles:", err)
		return 2
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: org_roles scan:", err)
			return 2
		}
		roleNames = append(roleNames, n)
	}
	rows.Close()
	findings = append(findings, evaluateAuditOrgRoles(roleNames)...)

	var resources []auditResourceRow
	rows, err = pool.Query(ctx, auditPreupgradeQueries["api_resources"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: api_resources:", err)
		return 2
	}
	for rows.Next() {
		var id uuid.UUID
		var r auditResourceRow
		if err := rows.Scan(&id, &r.Name, &r.Audience, &r.TTL, &r.Scopes); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: api_resources scan:", err)
			return 2
		}
		resources = append(resources, r)
	}
	rows.Close()
	findings = append(findings, evaluateAuditResources(resources)...)

	var templates []auditTemplateRow
	rows, err = pool.Query(ctx, auditPreupgradeQueries["scope_templates"])
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: scope_templates:", err)
		return 2
	}
	for rows.Next() {
		var r auditTemplateRow
		if err := rows.Scan(&r.Name, &r.Scopes); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: audit-preupgrade: scope_templates scan:", err)
			return 2
		}
		templates = append(templates, r)
	}
	rows.Close()
	findings = append(findings, evaluateAuditTemplates(templates)...)

	fmt.Fprintf(stdout, "audit-preupgrade: swept %d organizations, %d users, %d clients, %d service accounts, %d org roles, %d api resources, %d scope templates\n",
		len(orgs), len(emails), len(clients), len(sas), len(roleNames), len(resources), len(templates))
	if len(findings) == 0 {
		fmt.Fprintln(stdout, "audit-preupgrade: CLEAN — no stored row matches a shape the guards refuse")
		return 0
	}
	fmt.Fprintln(stdout, "audit-preupgrade: FINDINGS — rows the current guards refuse:")
	for _, f := range findings {
		fmt.Fprintf(stdout, "  %-16s %-52s count=%-4d rule=%s\n    %s\n", f.Entity, f.Shape, f.Count, f.RuleID, f.Impact)
	}
	fmt.Fprintln(stdout, "audit-preupgrade: see docs/TESTING-OPERATORS.md (pre-upgrade audit) for what to do about each shape")
	return 1
}
