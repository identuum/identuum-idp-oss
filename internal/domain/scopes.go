package domain

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ============================================================================
// Scope Constants (resource:action)
// ============================================================================

const (
	// Reports
	ScopeReportsRead   = "reports:read"
	ScopeReportsExport = "reports:export"

	// Audit
	ScopeAuditRead   = "audit:read"
	ScopeAuditExport = "audit:export"

	// Users
	ScopeUsersRead          = "users:read"
	ScopeUsersCreate        = "users:create"
	ScopeUsersUpdate        = "users:update"
	ScopeUsersDisable       = "users:disable"
	ScopeUsersDelete        = "users:delete"
	ScopeUsersPasswordReset = "users:password:reset"
	ScopeUsersMFAEnroll     = "users:mfa:enroll"
	ScopeUsersMFARevoke     = "users:mfa:revoke"

	// Organizations
	ScopeOrgsRead           = "orgs:read"
	ScopeOrgsCreate         = "orgs:create"
	ScopeOrgsUpdate         = "orgs:update"
	ScopeOrgsDisable        = "orgs:disable"
	ScopeOrgsDelete         = "orgs:delete"
	ScopeOrgsSettingsUpdate = "orgs:settings:update"

	// Sessions
	ScopeSessionsRead   = "sessions:read"
	ScopeSessionsRevoke = "sessions:revoke"

	// M2M / Service Accounts
	ScopeM2MRead    = "m2m:read"
	ScopeM2MCreate  = "m2m:create"
	ScopeM2MUpdate  = "m2m:update"
	ScopeM2MDisable = "m2m:disable"
	ScopeM2MDelete  = "m2m:delete"

	// Keys
	ScopeKeysRead   = "keys:read"
	ScopeKeysRotate = "keys:rotate"
	ScopeKeysRevoke = "keys:revoke"

	// Webhooks
	ScopeWebhooksRead   = "webhooks:read"
	ScopeWebhooksCreate = "webhooks:create"
	ScopeWebhooksUpdate = "webhooks:update"
	ScopeWebhooksDelete = "webhooks:delete"
	ScopeWebhooksTest   = "webhooks:test"

	// Backups
	ScopeBackupsRead    = "backups:read"
	ScopeBackupsCreate  = "backups:create"
	ScopeBackupsRestore = "backups:restore"
	ScopeBackupsDelete  = "backups:delete"

	// Org-scoped Backups (§10.A).
	// Distinct from backups:* which gates the site-admin pg_dump surface.
	// All three are granted to org_admin only; site_admin is explicitly blocked.
	ScopeOrgBackupsCreate  = "org_backups:create"
	ScopeOrgBackupsRead    = "org_backups:read"
	ScopeOrgBackupsRestore = "org_backups:restore"

	// System
	ScopeSystemMetrics    = "system:metrics"
	ScopeSystemConfigRead = "system:config:read"

	ScopeSystemConfigUpdate = "system:config:update"

	// Identity Providers
	ScopeIDPsRead   = "idps:read"
	ScopeIDPsCreate = "idps:create"
	ScopeIDPsUpdate = "idps:update"
	ScopeIDPsDelete = "idps:delete"

	// OAuth clients (ORG-ADMIN-SCOPES). The clients surface was
	// site_admin-only, so no scope names existed for it; the org-bound
	// org_admin opening needs them.
	ScopeClientsRead   = "clients:read"
	ScopeClientsCreate = "clients:create"
	ScopeClientsUpdate = "clients:update"
	ScopeClientsDelete = "clients:delete"

	// Trusted Assertion Issuers (Phase 5.2.c — RFC 8693 / 7523 trust registry)
	ScopeTrustedAssertionIssuersRead   = "trusted_assertion_issuers:read"
	ScopeTrustedAssertionIssuersCreate = "trusted_assertion_issuers:create"
	ScopeTrustedAssertionIssuersUpdate = "trusted_assertion_issuers:update"
	ScopeTrustedAssertionIssuersDelete = "trusted_assertion_issuers:delete"

	// OIDC Standard Scopes
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"

	// MCP (Model Context Protocol) -- legacy family. Retained because the
	// LiteLLM gateway's custom_auth hook continues to enforce mcp:access_ro
	// and mcp:access_rw on its inbound traffic (it has production consumers
	// via the LLM Token Dispensary CLI). Phase 3 migrated the embedded MCP
	// server at /mcp off this family onto identuum-admin:* below; the legacy
	// strings no longer satisfy the MCP server's gate, only the gateway's.
	ScopeMCPReadOnly  = "mcp:access_ro"
	ScopeMCPReadWrite = "mcp:access_rw"
	ScopeMCPAdmin     = "mcp:access_admin"

	// identuum-admin family -- consumed by the embedded MCP server at /mcp
	// for delegating Identuum administrative operations (user/org/audit
	// reads, user mutations). Replaced the legacy mcp:access_* family at the
	// MCP server gate in Phase 3. The supersedes relationship is preserved:
	// identuum-admin:admin alone is sufficient (no need to also hold :read
	// or :write). See docs/audit/litellm_phase_3_delta.md for the rename
	// rationale and the partition between this family and the legacy one.
	ScopeIdentuumAdminRead  = "identuum-admin:read"
	ScopeIdentuumAdminWrite = "identuum-admin:write"
	ScopeIdentuumAdminAdmin = "identuum-admin:admin"

	// Connector tag — LiteLLM. Identifies an M2M client that belongs to a
	// LiteLLM connector deployment. The scope is a tag, not a permission:
	// it does NOT gate any capability today. Connector operations
	// (RFC 7662 introspection, gateway-callback POSTs over HMAC) do not
	// consult bearer scopes. The tag exists so operators can grep audit
	// logs for connector-class clients and so future connector-class
	// behaviour gating has a hook without cross-cutting the rest of the
	// scope catalog. Wildcard expansion for the connector:* family is
	// explicitly NOT supported — the only family with structural
	// wildcards is llm:invoke:* (see ScopeMatchesLLMInvoke).
	ScopeConnectorLiteLLM = "connector:litellm"
)

// allScopes is a set of all valid scopes for validation
// Unexported to prevent external mutation
var allScopes = map[string]struct{}{
	ScopeReportsRead:                   {},
	ScopeReportsExport:                 {},
	ScopeAuditRead:                     {},
	ScopeAuditExport:                   {},
	ScopeUsersRead:                     {},
	ScopeUsersCreate:                   {},
	ScopeUsersUpdate:                   {},
	ScopeUsersDisable:                  {},
	ScopeUsersDelete:                   {},
	ScopeUsersPasswordReset:            {},
	ScopeUsersMFAEnroll:                {},
	ScopeUsersMFARevoke:                {},
	ScopeOrgsRead:                      {},
	ScopeOrgsCreate:                    {},
	ScopeOrgsUpdate:                    {},
	ScopeOrgsDisable:                   {},
	ScopeOrgsDelete:                    {},
	ScopeOrgsSettingsUpdate:            {},
	ScopeSessionsRead:                  {},
	ScopeSessionsRevoke:                {},
	ScopeM2MRead:                       {},
	ScopeM2MCreate:                     {},
	ScopeM2MUpdate:                     {},
	ScopeM2MDisable:                    {},
	ScopeM2MDelete:                     {},
	ScopeKeysRead:                      {},
	ScopeKeysRotate:                    {},
	ScopeKeysRevoke:                    {},
	ScopeWebhooksRead:                  {},
	ScopeWebhooksCreate:                {},
	ScopeWebhooksUpdate:                {},
	ScopeWebhooksDelete:                {},
	ScopeWebhooksTest:                  {},
	ScopeBackupsRead:                   {},
	ScopeBackupsCreate:                 {},
	ScopeBackupsRestore:                {},
	ScopeBackupsDelete:                 {},
	ScopeOrgBackupsCreate:              {},
	ScopeOrgBackupsRead:                {},
	ScopeOrgBackupsRestore:             {},
	ScopeSystemMetrics:                 {},
	ScopeSystemConfigRead:              {},
	ScopeSystemConfigUpdate:            {},
	ScopeIDPsRead:                      {},
	ScopeIDPsCreate:                    {},
	ScopeIDPsUpdate:                    {},
	ScopeIDPsDelete:                    {},
	ScopeClientsRead:                   {},
	ScopeClientsCreate:                 {},
	ScopeClientsUpdate:                 {},
	ScopeClientsDelete:                 {},
	ScopeTrustedAssertionIssuersRead:   {},
	ScopeTrustedAssertionIssuersCreate: {},
	ScopeTrustedAssertionIssuersUpdate: {},
	ScopeTrustedAssertionIssuersDelete: {},
	ScopeOpenID:                        {},
	ScopeProfile:                       {},
	ScopeEmail:                         {},
	ScopeOfflineAccess:                 {},
	ScopeMCPReadOnly:                   {},
	ScopeMCPReadWrite:                  {},
	ScopeMCPAdmin:                      {},
	ScopeIdentuumAdminRead:             {},
	ScopeIdentuumAdminWrite:            {},
	ScopeIdentuumAdminAdmin:            {},
	ScopeConnectorLiteLLM:              {},
}

// ============================================================================
// Helpers
// ============================================================================

// IsKnownScope checks if a single scope string is valid for core Identuum operations
func IsKnownScope(scope string) bool {
	_, ok := allScopes[scope]
	return ok
}

// FilterKnownScopes takes a space-delimited string and returns ONLY the scopes
// that are known in the allowed list, as a map for fast lookup.
// Useful for sanitizing tokens from legacy systems or external inputs.
func FilterKnownScopes(scopeStr string) map[string]struct{} {
	scopes := make(map[string]struct{})
	parts := strings.Fields(scopeStr)
	for _, part := range parts {
		if IsKnownScope(part) {
			scopes[part] = struct{}{}
		}
	}
	return scopes
}

// ValidateScopes checks if all requested scopes are in the known list
// It normalizes inputs (trim space) and returns one wrapped error per unknown scope,
// joined via errors.Join so callers can inspect individual failures with errors.Is/As.
func ValidateScopes(requested []string) error {
	unknownSet := make(map[string]struct{})
	for _, req := range requested {
		normalized := strings.TrimSpace(req)
		if normalized == "" {
			continue
		}
		if !IsKnownScope(normalized) {
			unknownSet[normalized] = struct{}{}
		}
	}

	if len(unknownSet) == 0 {
		return nil
	}

	// Sort for stable error messages
	unknown := make([]string, 0, len(unknownSet))
	for u := range unknownSet {
		unknown = append(unknown, u)
	}
	sort.Strings(unknown)

	errs := make([]error, len(unknown))
	for i, u := range unknown {
		errs[i] = fmt.Errorf("unknown scope: %s", u)
	}
	return errors.Join(errs...)
}

// HasAnyScope checks if the provided set contains at least one of the required scopes
func HasAnyScope(heldScopes map[string]struct{}, required []string) bool {
	if len(heldScopes) == 0 || len(required) == 0 {
		return false
	}
	for _, req := range required {
		if _, ok := heldScopes[req]; ok {
			return true
		}
	}
	return false
}

// LLMInvokeScopePrefix is the only scope prefix for which wildcard matching
// is activated. Every other scope prefix (mcp:access_*, identuum-admin:*,
// users:*, every existing or future family) uses literal-string equality.
// This boundary is enforced structurally in ScopeMatchesLLMInvoke and
// locked by tests that assert wildcards do NOT extend to other families.
const LLMInvokeScopePrefix = "llm:invoke:"

// ErrInvalidLLMInvokeScope is returned by ValidateLLMInvokeScope when a
// scope that begins with LLMInvokeScopePrefix is structurally malformed.
// Wrapped with the offending scope string by callers (the client-service
// grant-time validator) so admin UI surfaces the bad input directly.
var ErrInvalidLLMInvokeScope = errors.New("malformed llm:invoke scope")

// llmInvokeProviderRE is the lowercase-alphanumerics-and-hyphens-or-underscores
// pattern used for provider segments. Compiled at init time; cheap to reuse.
//
// Model segments are validated more loosely (any non-empty string that does
// not start with `*` and does not contain `:`) so we don't lock out
// vendor-specific model identifiers like `gpt-4o-mini-2024-07-18` or
// `claude-sonnet-4-5`.
var llmInvokeProviderRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// ValidateLLMInvokeScope returns nil when scope is a well-formed
// llm:invoke:<provider>:<model>, llm:invoke:<provider>:*, or llm:invoke:*
// string, and ErrInvalidLLMInvokeScope wrapped with detail otherwise.
//
// Strings whose prefix is NOT LLMInvokeScopePrefix are accepted
// unconditionally (they are out of scope for this validator -- the
// "scopes are intentionally not validated against the static list"
// invariant in domain/client.go applies to them). Callers that want
// blanket validation should use ValidateScopes instead.
//
// Legal forms:
//
//	llm:invoke:*                                   (global wildcard)
//	llm:invoke:<lowercase-provider>:*              (per-provider wildcard)
//	llm:invoke:<lowercase-provider>:<model>        (literal)
//
// Reject forms (with a clear error each):
//
//	llm:invoke                       -- missing provider+model
//	llm:invoke:                      -- empty provider+model
//	llm:invoke:anthropic             -- missing model
//	llm:invoke:anthropic:            -- empty model
//	llm:invoke:Anthropic:claude-...  -- uppercase provider
//	llm:invoke:*:*                   -- multiple wildcards
//	llm:invoke:*:claude-...          -- non-trailing wildcard
//	llm:invoke:anthropic:claude-*    -- partial-model wildcard
func ValidateLLMInvokeScope(scope string) error {
	// "llm:invoke" without trailing colon is treated as a malformed
	// llm:invoke-family scope, not as out-of-scope. Operators who
	// fat-finger the colon get a clear rejection.
	if scope == "llm:invoke" {
		return fmt.Errorf("%w: %q is missing provider and model", ErrInvalidLLMInvokeScope, scope)
	}
	if !strings.HasPrefix(scope, LLMInvokeScopePrefix) {
		return nil // out of scope for this validator
	}
	tail := scope[len(LLMInvokeScopePrefix):]
	if tail == "" {
		return fmt.Errorf("%w: %q is missing provider and model", ErrInvalidLLMInvokeScope, scope)
	}
	if tail == "*" {
		return nil // global wildcard
	}
	parts := strings.Split(tail, ":")
	if len(parts) != 2 {
		return fmt.Errorf("%w: %q must be llm:invoke:<provider>:<model> or llm:invoke:<provider>:* (got %d colons)", ErrInvalidLLMInvokeScope, scope, len(parts))
	}
	provider, model := parts[0], parts[1]
	if provider == "*" {
		return fmt.Errorf("%w: %q has wildcard in provider position; only the trailing-wildcard form is valid", ErrInvalidLLMInvokeScope, scope)
	}
	if !llmInvokeProviderRE.MatchString(provider) {
		return fmt.Errorf("%w: %q has malformed provider %q (must match [a-z0-9_-]+)", ErrInvalidLLMInvokeScope, scope, provider)
	}
	if model == "" {
		return fmt.Errorf("%w: %q has empty model segment", ErrInvalidLLMInvokeScope, scope)
	}
	if model == "*" {
		return nil // per-provider wildcard
	}
	if strings.ContainsRune(model, '*') {
		return fmt.Errorf("%w: %q has partial-wildcard in model %q; only the bare * form is valid", ErrInvalidLLMInvokeScope, scope, model)
	}
	return nil
}

// ScopeMatchesLLMInvoke returns true when the JWT scope satisfies the
// requested required scope under the llm:invoke:* family's wildcard
// rules. For required scopes outside the llm:invoke:* prefix, falls
// back to literal equality -- so wildcards do NOT leak to mcp:access_*,
// identuum-admin:*, or any other family.
//
// Defensive: if the JWT scope is malformed (multiple wildcards, or
// embedded `:` in the provider segment when wildcard is present), it is
// rejected here too. The grant-time validator should have caught the
// malformed strings before any token was minted with them, but this
// function is the second line of defence at the gateway.
//
// Mirrors the algorithm in tools/llm-gateway/litellm/custom_auth.py's
// _scope_matches_llm_invoke. Both implementations are <20 lines and
// must be kept in lockstep.
func ScopeMatchesLLMInvoke(jwtScope, requiredScope string) bool {
	if !strings.HasPrefix(requiredScope, LLMInvokeScopePrefix) {
		return jwtScope == requiredScope
	}
	if jwtScope == LLMInvokeScopePrefix+"*" {
		return true // global wildcard
	}
	if !strings.HasPrefix(jwtScope, LLMInvokeScopePrefix) {
		return false // jwt is from another family entirely
	}
	if !strings.HasSuffix(jwtScope, ":*") {
		return jwtScope == requiredScope // literal jwt match
	}
	// Per-provider wildcard: jwtScope = "llm:invoke:<P>:*"
	provider := jwtScope[len(LLMInvokeScopePrefix) : len(jwtScope)-2]
	if provider == "" || strings.ContainsRune(provider, ':') || strings.ContainsRune(provider, '*') {
		return false // malformed jwt scope
	}
	return strings.HasPrefix(requiredScope, LLMInvokeScopePrefix+provider+":")
}

// OrgAdminSessionScopes is the role-derived scope set a password-login
// SESSION token carries for an org_admin (ORG-ADMIN-SCOPES, owner ruling:
// "session tokens CARRY role-derived scopes, ORG-BOUND").
//
// Before this existed, a freshly delegated org_admin was 403 on EVERY
// administrative route: the guards (RequireSiteAdminOrOrgAdminWithScopes*)
// read the scope claim, a session token carried none, and the org-role RBAC
// chain could not help — those roles bind scopes to API RESOURCES
// (AddScopeForActor requires a resource_id), a different surface. An
// org_admin could not create the first user in its own organization.
//
// ORG-BOUND is not encoded in the scope strings; it is enforced where the
// work happens: the *ForActor service methods pin an org_admin's writes to
// actor.OrganizationID (users, service accounts), the SameOrg guards match
// the URL org, and the clients surface filters by the actor's org. The scope
// says WHAT an org_admin may do; the actor's org says WHERE.
//
// Deliberately absent: orgs:create/disable/delete (org lifecycle is
// infrastructure authority), keys:*, backups:*, system:* (site scope),
// audit:export (site scope; audit:read is org-scoped).
var OrgAdminSessionScopes = []string{
	ScopeUsersRead, ScopeUsersCreate, ScopeUsersUpdate, ScopeUsersDisable,
	ScopeUsersDelete, ScopeUsersPasswordReset, ScopeUsersMFAEnroll, ScopeUsersMFARevoke,
	ScopeOrgsRead, ScopeOrgsUpdate, ScopeOrgsSettingsUpdate,
	ScopeSessionsRead, ScopeSessionsRevoke,
	ScopeM2MRead, ScopeM2MCreate, ScopeM2MUpdate, ScopeM2MDisable, ScopeM2MDelete,
	ScopeClientsRead, ScopeClientsCreate, ScopeClientsUpdate, ScopeClientsDelete,
	ScopeIDPsRead, ScopeIDPsCreate, ScopeIDPsUpdate, ScopeIDPsDelete,
	ScopeAuditRead,
}

// SessionScopesForRole returns the scope string a session token carries for
// the given role. site_admin needs none (every guard short-circuits on the
// role); org_user gets none (it administers nothing); org_admin gets
// OrgAdminSessionScopes.
func SessionScopesForRole(role UserRole) string {
	if role == RoleOrgAdmin {
		return strings.Join(OrgAdminSessionScopes, " ")
	}
	return ""
}
