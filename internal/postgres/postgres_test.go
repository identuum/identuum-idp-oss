package postgres

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
)

// TestNewPgxRepositories_AllFieldsPopulated verifies the OSS factory
// returns a non-nil aggregate with every repository field bound to a
// non-nil concrete implementation. nil DBTX is passed because every
// pgx constructor simply stashes the reference without dereferencing,
// so no DB call occurs and no panic is expected.
func TestNewPgxRepositories_AllFieldsPopulated(t *testing.T) {
	repos := NewPgxRepositories(nil, nil)

	require.NotNil(t, repos, "NewPgxRepositories must not return nil")

	assert.NotNil(t, repos.User, "User repository must be populated")
	assert.NotNil(t, repos.AdminUser, "AdminUser repository must be populated")
	assert.NotNil(t, repos.Organization, "Organization repository must be populated")
	assert.NotNil(t, repos.Session, "Session repository must be populated")
	assert.NotNil(t, repos.AuthCode, "AuthCode repository must be populated")
	assert.NotNil(t, repos.Client, "Client repository must be populated")
	assert.NotNil(t, repos.Key, "Key repository must be populated")
	assert.NotNil(t, repos.PasswordReset, "PasswordReset repository must be populated")
	assert.NotNil(t, repos.IdentityProvider, "IdentityProvider repository must be populated")
	assert.NotNil(t, repos.OIDCState, "OIDCState repository must be populated")
	assert.NotNil(t, repos.Claim, "Claim repository must be populated")
	assert.NotNil(t, repos.APIResource, "APIResource repository must be populated")
	assert.NotNil(t, repos.OrgRole, "OrgRole repository must be populated")
	assert.NotNil(t, repos.OrganizationDomain, "OrganizationDomain repository must be populated")
	assert.NotNil(t, repos.ScopeTemplate, "ScopeTemplate repository must be populated")
	assert.NotNil(t, repos.ServiceAccount, "ServiceAccount repository must be populated")
	assert.NotNil(t, repos.WebAuthnCredential, "WebAuthnCredential repository must be populated")
	assert.NotNil(t, repos.EmailVerification, "EmailVerification repository must be populated")
	assert.NotNil(t, repos.AgentCommunicationAuthorization, "AgentCommunicationAuthorization repository must be populated")
	assert.NotNil(t, repos.DPoPProofReplay, "DPoPProofReplay repository must be populated")
	assert.NotNil(t, repos.AgentCommunicationToken, "AgentCommunicationToken repository must be populated")
}

// TestNewPgxRepositories_AdminUserSharesUserInstance verifies that the
// AdminUser and User fields point to the same underlying concrete
// instance. PgxUserRepository satisfies both interfaces; reusing one
// allocation here mirrors the monolith pattern.
func TestNewPgxRepositories_AdminUserSharesUserInstance(t *testing.T) {
	repos := NewPgxRepositories(nil, nil)

	require.NotNil(t, repos.User)
	require.NotNil(t, repos.AdminUser)

	// Both fields are interface values backed by the same concrete
	// *PgxUserRepository pointer. The interface equality below holds
	// because the underlying dynamic type AND pointer are identical.
	assert.Equal(t, repos.User, repos.AdminUser,
		"AdminUser must share the same underlying instance as User")
}

// TestApplyCachedWrappers_NilRedisIsNoOp verifies the cache helper is
// safe to call with a nil RedisClient. Production bootstrap can then
// invoke ApplyCachedWrappers unconditionally and rely on this no-op
// behavior when Redis is unconfigured.
func TestApplyCachedWrappers_NilRedisIsNoOp(t *testing.T) {
	repos := NewPgxRepositories(nil, nil)

	before := *repos

	assert.NotPanics(t, func() {
		ApplyCachedWrappers(repos, nil, 0)
	})

	assert.Equal(t, before.User, repos.User, "User must be unchanged when redis is nil")
	assert.Equal(t, before.Organization, repos.Organization, "Organization must be unchanged when redis is nil")
	assert.Equal(t, before.Session, repos.Session, "Session must be unchanged when redis is nil")
	assert.Equal(t, before.Client, repos.Client, "Client must be unchanged when redis is nil")
	assert.Equal(t, before.IdentityProvider, repos.IdentityProvider, "IdentityProvider must be unchanged when redis is nil")
	assert.Equal(t, before.ServiceAccount, repos.ServiceAccount, "ServiceAccount must be unchanged when redis is nil")
}

// TestApplyCachedWrappers_NilReposIsNoOp verifies the helper handles a
// nil Repositories pointer defensively. A panic here would crash any
// caller that misuses the API; the explicit guard is cheap insurance.
func TestApplyCachedWrappers_NilReposIsNoOp(t *testing.T) {
	assert.NotPanics(t, func() {
		ApplyCachedWrappers(nil, nil, 0)
	})
}

// TestApplyCachedWrappers_AppliedSetIsPinned pins the P3-11 verdict: with a
// NON-nil redis client, ApplyCachedWrappers applies EXACTLY the proven-safe
// wrapper set — which is EMPTY today, because every one of the six cached
// wrappers caches at least one read whose pgx delegate carries a
// tenant/liveness predicate a cache hit would bypass (the per-wrapper
// predicate list, with file:line, lives on ApplyCachedWrappers itself).
// Re-adding a wrapper line without updating this test turns it RED — the
// applied set cannot grow silently. If you are here because it went red:
// bring a liveness verdict for EVERY cached read of the wrapper you are
// adding, then extend the expected set below deliberately.
func TestApplyCachedWrappers_AppliedSetIsPinned(t *testing.T) {
	repos := NewPgxRepositories(nil, nil)
	before := *repos

	// A non-nil client with a zero inner handle: wrapping (if any were
	// wrongly re-added) only stores the pointer, so no redis I/O happens
	// in this test either way.
	ApplyCachedWrappers(repos, &cache.RedisClient{}, time.Minute)

	// The WHOLE struct is the pin, not a field list. Asserting only the six
	// fields that historically had cached wrappers would let a decorator on
	// any OTHER Repositories field (AuthCode, RefreshToken, …) land green —
	// an enumerated pin re-creates the exact allow-list failure this slice
	// closed (standing lesson 8: a guard over a set must derive/cover the
	// set, never enumerate it). The comparison is per-field POINTER IDENTITY
	// via reflection, not deep equality: assert.Equal's DeepEqual would pass
	// a same-type re-instance (two &PgxAuthCodeRepository{db:nil} are deeply
	// equal), so identity is the only comparison that proves the exact
	// delegate instances survived untouched — and it enumerates nothing, so
	// a 29th Repositories field is covered the day it is added.
	bt := reflect.TypeOf(before)
	bv := reflect.ValueOf(before)
	av := reflect.ValueOf(*repos)
	for i := 0; i < bt.NumField(); i++ {
		assert.True(t, bv.Field(i).Interface() == av.Field(i).Interface(),
			"Repositories.%s was swapped by ApplyCachedWrappers — no wrapper on ANY field is liveness-proved (see the list on ApplyCachedWrappers)", bt.Field(i).Name)
	}

	// Per-field diagnostics for the six wrappers that exist today — redundant
	// with the whole-struct pin above, kept because their messages carry the
	// per-wrapper predicate a cache hit would bypass.
	assert.Equal(t, before.User, repos.User, "User must NOT be wrapped (cache hit would bypass banned/deleted filters — see ApplyCachedWrappers)")
	assert.Equal(t, before.Organization, repos.Organization, "Organization must NOT be wrapped (cache hit would bypass active/deleted filters)")
	assert.Equal(t, before.Session, repos.Session, "Session must NOT be wrapped (would cache the P0-4/5 combined status verdict)")
	assert.Equal(t, before.Client, repos.Client, "Client must NOT be wrapped (cache hit would bypass the org-liveness EXISTS)")
	assert.Equal(t, before.IdentityProvider, repos.IdentityProvider, "IdentityProvider must NOT be wrapped (cache hit would bypass the org-liveness EXISTS)")
	assert.Equal(t, before.ServiceAccount, repos.ServiceAccount, "ServiceAccount must NOT be wrapped (cache hit would bypass deleted_at IS NULL)")
}
