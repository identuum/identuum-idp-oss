package domain_test

import (
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKnownScope(t *testing.T) {
	assert.True(t, domain.IsKnownScope(domain.ScopeUsersRead))
	assert.True(t, domain.IsKnownScope("openid"))
	assert.False(t, domain.IsKnownScope("unknown:scope"))
	assert.False(t, domain.IsKnownScope(""))
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name        string
		errContains string
		requested   []string
		wantErr     bool
	}{
		{
			name:      "Valid Scopes",
			requested: []string{domain.ScopeUsersRead, "openid"},
			wantErr:   false,
		},
		{
			name:      "Empty Scopes",
			requested: []string{},
			wantErr:   false,
		},
		{
			name:        "Unknown Scope",
			requested:   []string{"invalid:scope"},
			wantErr:     true,
			errContains: "unknown scope: invalid:scope",
		},
		{
			name:      "Multiple Unknown Scopes - Sorted",
			requested: []string{"z:scope", "a:scope", domain.ScopeUsersRead},
			wantErr:   true,
			// errors.Join produces: "unknown scope: a:scope\nunknown scope: z:scope"
			errContains: "unknown scope: a:scope",
		},
		{
			name:      "Whitespace Handling",
			requested: []string{" openid ", "  ", domain.ScopeUsersRead},
			wantErr:   false,
		},
		{
			name:        "Deduplication",
			requested:   []string{"bad:scope", "bad:scope"},
			wantErr:     true,
			errContains: "unknown scope: bad:scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateScopes(tt.requested)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestConnectorLiteLLMScope pins the connector:litellm tagging scope's
// catalog contract: the constant resolves to its literal string and is
// registered in the central allScopes validation map. Behavioural
// assertions for the M2M scope-resolution helper and the org-admin grant
// validator live next to those code paths
// (service/client_service_m2m_helpers_test.go and
// service/client_service_scope_test.go respectively) — they exercise
// service-layer code and cannot be expressed at the domain layer.
func TestConnectorLiteLLMScope(t *testing.T) {
	t.Run("constant resolves to literal connector:litellm", func(t *testing.T) {
		assert.Equal(t, "connector:litellm", domain.ScopeConnectorLiteLLM)
	})

	t.Run("constant is registered in the central validation map", func(t *testing.T) {
		assert.True(t, domain.IsKnownScope(domain.ScopeConnectorLiteLLM),
			"connector:litellm must be present in allScopes so M2M scope resolution"+
				" treats it as a static scope rather than falling through to the"+
				" dynamic api-resource branch and rejecting it")
	})
}

func TestFilterKnownScopes(t *testing.T) {
	input := "openid unknown:scope users:read bad:thing"
	filteredMap := domain.FilterKnownScopes(input)

	assert.Len(t, filteredMap, 2)
	assert.Contains(t, filteredMap, "openid")
	assert.Contains(t, filteredMap, domain.ScopeUsersRead)
	assert.NotContains(t, filteredMap, "unknown:scope")
}

// =============================================================================
// Phase 4: parameterized llm:invoke:<provider>:<model> scope family.
// =============================================================================

func TestValidateLLMInvokeScope_Accepts(t *testing.T) {
	cases := []string{
		"llm:invoke:*",           // global wildcard
		"llm:invoke:anthropic:*", // per-provider wildcard
		"llm:invoke:anthropic:claude-sonnet-4-5",
		"llm:invoke:openai:gpt-4o",
		"llm:invoke:openai:gpt-4o-mini-2024-07-18", // multi-segment hyphenated model
		"llm:invoke:google:gemini-1.5-pro",         // dots and hyphens permitted in model
		"llm:invoke:my_custom_provider:my-model",   // underscores in provider
		"users:read",                               // non-llm:invoke prefix is out of scope -> nil
		"identuum-admin:read",                      // ditto
		"",                                         // empty string is out of scope -> nil
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			assert.NoError(t, domain.ValidateLLMInvokeScope(c), "scope %q must be accepted", c)
		})
	}
}

func TestValidateLLMInvokeScope_Rejects(t *testing.T) {
	cases := []struct {
		scope, contain string
	}{
		{"llm:invoke", "missing provider"},
		{"llm:invoke:", "missing provider"},
		{"llm:invoke:anthropic", "must be llm:invoke:<provider>:<model>"},
		{"llm:invoke:anthropic:", "empty model segment"},
		{"llm:invoke:Anthropic:claude-sonnet-4-5", "malformed provider"},
		{"llm:invoke:*:*", "wildcard in provider position"},
		{"llm:invoke:*:claude-sonnet-4-5", "wildcard in provider position"},
		{"llm:invoke:anthropic:claude-*", "partial-wildcard in model"},
		{"llm:invoke:anthropic:claude-sonnet-*-5", "partial-wildcard in model"},
		{"llm:invoke:my:provider:model", "must be llm:invoke:"}, // too many colons
	}
	for _, c := range cases {
		t.Run(c.scope, func(t *testing.T) {
			err := domain.ValidateLLMInvokeScope(c.scope)
			require.Error(t, err)
			assert.True(t, errors.Is(err, domain.ErrInvalidLLMInvokeScope), "must wrap sentinel; got %v", err)
			assert.Contains(t, err.Error(), c.contain)
		})
	}
}

func TestScopeMatchesLLMInvoke(t *testing.T) {
	cases := []struct {
		name, jwt, required string
		want                bool
	}{
		{"M1_literal_match", "llm:invoke:anthropic:claude-sonnet-4-5", "llm:invoke:anthropic:claude-sonnet-4-5", true},
		{"M2_literal_mismatch_provider", "llm:invoke:anthropic:claude-sonnet-4-5", "llm:invoke:openai:gpt-4o", false},
		{"M3_per_provider_wildcard_matches", "llm:invoke:anthropic:*", "llm:invoke:anthropic:claude-sonnet-4-5", true},
		{"M3b_per_provider_wildcard_matches_other_model", "llm:invoke:anthropic:*", "llm:invoke:anthropic:claude-3-opus", true},
		{"M4_per_provider_wildcard_other_provider_rejects", "llm:invoke:anthropic:*", "llm:invoke:openai:gpt-4o", false},
		{"M5_global_wildcard_matches_anthropic", "llm:invoke:*", "llm:invoke:anthropic:claude-sonnet-4-5", true},
		{"M6_global_wildcard_matches_openai", "llm:invoke:*", "llm:invoke:openai:gpt-4o", true},
		{"M7_non_llm_jwt_scope_rejects_llm_required", "mcp:access_ro", "llm:invoke:anthropic:claude-sonnet-4-5", false},
		{"M8_unrelated_scope_rejects", "users:read", "llm:invoke:anthropic:claude-sonnet-4-5", false},
		// =====================================================================
		// Boundary tests: wildcards do NOT leak to other scope families.
		// These lock the structural property the brief specifically calls for.
		// =====================================================================
		{"M9_BOUNDARY_mcp_access_wildcard_does_not_match_literal", "mcp:access:*", "mcp:access_ro", false},
		{"M10_BOUNDARY_identuum_admin_wildcard_does_not_match_literal", "identuum-admin:*", "identuum-admin:read", false},
		{"M11_BOUNDARY_users_wildcard_does_not_match_literal", "users:*", "users:read", false},
		// Same-family literal-on-both-sides still works.
		{"M12_non_llm_literal_match", "users:read", "users:read", true},
		// Defensive: malformed jwt with double-wildcard does not match anything.
		{"M13_defensive_malformed_jwt", "llm:invoke:*:*", "llm:invoke:anthropic:claude-sonnet-4-5", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := domain.ScopeMatchesLLMInvoke(c.jwt, c.required)
			assert.Equal(t, c.want, got, "ScopeMatchesLLMInvoke(jwt=%q, required=%q)", c.jwt, c.required)
		})
	}
}
