package service

// claim_service_test.go — unit tests for the OSS ClaimService.
// Covered:
//
//   - generate: rejects nil org / missing org;
//   - generate: success → hash persisted (raw never stored), audit emitted;
//   - validate: empty / unknown / expired / max-attempts → {Valid:false};
//   - validate: happy path → {Valid:true, OrganizationName};
//   - consume: bad email / weak password / unknown token → {Success:false};
//   - consume: email-bound mismatch → {Success:false} + attempt incremented;
//   - consume: max-attempts → burns token, returns AttemptsExhausted;
//   - consume: org already active → {Success:false} + burns token;
//   - consume happy path → creates org_admin + deletes claim + audit emit;
//   - consume replay after burn → {Success:false};
//   - audit metadata never contains the raw token.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- claim repo fake ----------

type fakeClaimRepo struct {
	mu     sync.Mutex
	byHash map[string]*domain.OrganizationClaim
	byID   map[uuid.UUID]*domain.OrganizationClaim
}

func newFakeClaimRepo() *fakeClaimRepo {
	return &fakeClaimRepo{
		byHash: make(map[string]*domain.OrganizationClaim),
		byID:   make(map[uuid.UUID]*domain.OrganizationClaim),
	}
}

func (r *fakeClaimRepo) Create(_ context.Context, c *domain.OrganizationClaim) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *c
	r.byHash[c.TokenHash] = &cp
	r.byID[c.ID] = &cp
	return nil
}

func (r *fakeClaimRepo) GetByTokenHash(_ context.Context, hash string) (*domain.OrganizationClaim, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byHash[hash]
	if !ok {
		return nil, domain.ErrClaimNotFound
	}
	return c, nil
}

func (r *fakeClaimRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		// P3-2: mirror production. A delete that removes nothing means a
		// concurrent claimant already burned the row, and the caller must be
		// told — the delete IS the mutex.
		return domain.ErrClaimNotFound
	}
	delete(r.byHash, c.TokenHash)
	delete(r.byID, id)
	return nil
}

func (r *fakeClaimRepo) DeleteExpired(context.Context) (int64, error) { return 0, nil }

func (r *fakeClaimRepo) IncrementAttemptCount(_ context.Context, id uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return 0, domain.ErrClaimNotFound
	}
	c.AttemptCount++
	return c.AttemptCount, nil
}

// ---------- fixtures ----------

func newClaimFixture(t *testing.T) (*ClaimService, *fakeClaimRepo, *fakeOrgRepo, *fakeUserRepo, *fakeAuditRecorder, *domain.Organization) {
	t.Helper()
	orgID := uuid.New()
	org := &domain.Organization{
		ID:      orgID,
		Name:    "Acme",
		Domain:  "acme.test",
		OrgSlug: "acme",
		Active:  false,
	}
	claims := newFakeClaimRepo()
	orgs := newFakeOrgRepo(org)
	users := newFakeUserRepo()
	rec := &fakeAuditRecorder{}
	svc := NewClaimService(ClaimServiceConfig{
		Claims:    claims,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Users:     users,
		Exists:    users,
		Audit:     rec,
	})
	return svc, claims, orgs, users, rec, org
}

// ---------- tests ----------

func TestGenerateClaimToken_NilOrgIDRejected(t *testing.T) {
	svc, _, _, _, _, _ := newClaimFixture(t)
	_, _, err := svc.GenerateClaimToken(context.Background(), uuid.Nil, "")
	assert.ErrorIs(t, err, ErrClaimInvalidRequest)
}

func TestGenerateClaimToken_HappyPath(t *testing.T) {
	svc, claims, _, _, rec, org := newClaimFixture(t)
	raw, expiresAt, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	assert.Len(t, raw, 64)
	assert.True(t, expiresAt.After(time.Now()))
	require.Len(t, claims.byHash, 1)
	hash := crypto.HashToken(raw)
	row, ok := claims.byHash[hash]
	require.True(t, ok, "raw token must hash to the persisted key")
	assert.Equal(t, org.ID, row.OrganizationID)
	assert.False(t, row.EmailBound)
	assert.Empty(t, row.TargetEmail)

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, domain.AuditClaimGenerated, events[0].Action)
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok {
			assert.False(t, strings.Contains(s, raw), "metadata key %q must not carry raw claim token", k)
		}
	}
}

func TestGenerateClaimToken_EmailBoundCarriesTargetEmail(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "Bound@Example.test")
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	row := claims.byHash[hash]
	require.NotNil(t, row)
	assert.True(t, row.EmailBound)
	assert.Equal(t, "bound@example.test", row.TargetEmail)
}

func TestValidateClaim_EmptyTokenIsInvalid(t *testing.T) {
	svc, _, _, _, _, _ := newClaimFixture(t)
	result, err := svc.ValidateClaim(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
}

func TestValidateClaim_UnknownTokenIsInvalid(t *testing.T) {
	svc, _, _, _, _, _ := newClaimFixture(t)
	result, err := svc.ValidateClaim(context.Background(), "no-such-token")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
}

func TestValidateClaim_ExpiredIsInvalid(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	id := uuid.New()
	claims.byHash[hash] = &domain.OrganizationClaim{
		ID:             id,
		OrganizationID: org.ID,
		TokenHash:      hash,
		ExpiresAt:      time.Now().Add(-time.Hour),
	}
	claims.byID[id] = claims.byHash[hash]

	result, err := svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
}

func TestValidateClaim_HappyPath(t *testing.T) {
	svc, _, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	result, err := svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, "Acme", result.OrganizationName)
}

func TestValidateClaim_EmailBoundExposesTargetEmail(t *testing.T) {
	svc, _, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "bound@example.test")
	require.NoError(t, err)
	result, err := svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, "bound@example.test", result.TargetEmail)
}

func TestConsumeClaim_EmptyTokenIsFailure(t *testing.T) {
	svc, _, _, _, _, _ := newClaimFixture(t)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestConsumeClaim_MissingEmailIsFailure(t *testing.T) {
	svc, _, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{Token: raw, Password: "longenoughpassword"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestConsumeClaim_WeakPasswordIncrementsAttempts(t *testing.T) {
	svc, _, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "short",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "weak_password", result.Reason)
	assert.NotNil(t, result.AttemptsRemaining)
}

func TestConsumeClaim_EmailBindingMismatchFailsAndIncrements(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "owner@example.test")
	require.NoError(t, err)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "intruder@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	hash := crypto.HashToken(raw)
	row := claims.byHash[hash]
	require.NotNil(t, row)
	assert.Equal(t, 1, row.AttemptCount, "binding-mismatch must increment attempt counter")
}

func TestConsumeClaim_MaxAttemptsBurns(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	claims.byHash[hash].AttemptCount = domain.ClaimMaxPasswordAttempts // pre-exhaust
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.AttemptsExhausted)
	assert.False(t, result.Success)
	// Row deleted after the burn.
	assert.Empty(t, claims.byHash)
}

func TestConsumeClaim_AlreadyActiveBurnsToken(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	org.Active = true
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Empty(t, claims.byHash, "claim row must be burned when org is already active")
}

func TestConsumeClaim_HappyPathMintsOrgAdmin(t *testing.T) {
	svc, claims, _, users, rec, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Name:     "Alice",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Empty(t, claims.byHash, "claim row must be burned on success")
	// New org_admin must exist.
	require.Len(t, users.byEmail["alice@example.test"], 1)
	created := users.byEmail["alice@example.test"][0]
	assert.Equal(t, domain.RoleOrgAdmin, created.Role)
	assert.Equal(t, org.ID, created.OrganizationID)
	assert.True(t, created.EmailVerified)

	events := rec.snapshot()
	// Two audit events: generate + consume.
	require.GreaterOrEqual(t, len(events), 2)
	actions := []string{}
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	assert.Contains(t, actions, domain.AuditClaimConsumed)
	// Raw token must not appear in any metadata value.
	for _, e := range events {
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok {
				assert.False(t, strings.Contains(s, raw),
					"metadata key %q must not carry raw claim token", k)
			}
		}
	}
}

func TestConsumeClaim_ReplayAfterBurnIsFailure(t *testing.T) {
	svc, _, _, _, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	_, err = svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestConsumeClaim_PreExistingAdminRejected(t *testing.T) {
	svc, _, _, users, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	// Pre-seed an existing admin with the same email in the org.
	id, _ := uuid.NewV7()
	existing := &domain.User{ID: id, Email: "alice@example.test", OrganizationID: org.ID, Role: domain.RoleOrgAdmin}
	users.byEmail["alice@example.test"] = []*domain.User{existing}
	users.byID[id] = existing

	result, err := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{
		Token:    raw,
		Email:    "alice@example.test",
		Password: "longenoughpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "email_exists", result.Reason)
}

func TestConsumeClaim_DiagnosticReasonHiddenOnWire(t *testing.T) {
	// Sanity pin: the service still emits an internal Reason
	// diagnostic (used by the handler to render attempts_remaining
	// and the max-attempts message), but the wire contract MUST
	// only surface Success / AttemptsRemaining / AttemptsExhausted
	// — never the Reason string. The handler test pins this.
	_ = audit.NoopService{}
}
