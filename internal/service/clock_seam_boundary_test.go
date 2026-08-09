package service

// clock_seam_boundary_test.go — the four exported `Now func() time.Time` seams,
// exercised at the one instant that decides their contract.
//
// WHY THIS FILE EXISTS (CLOCK-SEAM-UNUSED, 2026-08-02). PasswordResetServiceConfig,
// EmailVerificationServiceOptions, OrganizationActivationServiceConfig and
// ClaimServiceConfig each declare an exported `Now`, each default it to time.Now,
// and — measured by tools/clockfuse before this file — each had been injected
// ZERO times, with a clock of any kind. A seam nothing constructs and a seam every
// construction supplies correctly look identical to the omission detector: both
// report nothing. The field existed; it had never once done its job.
//
// WHAT EACH TEST ASSERTS IS A BOUNDARY THE WALL CLOCK CANNOT REACH: the instant
// EXACTLY equal to ExpiresAt. A wall-clock test can be before it or after it, and
// never on it — `time.Now()` will not return a nanosecond you chose. That is why
// removing the injection does not merely weaken these tests, it breaks them: the
// fixture's 2031 timestamps stop being what the service compares against.
//
// AND THE FOUR BOUNDARIES ARE NOT THE SAME, which is the point of pinning them:
//
//	PasswordReset          IsExpired = now.After(ExpiresAt)   -> at ExpiresAt: VALID
//	OrganizationActivation expired   = now.After(ExpiresAt)   -> at ExpiresAt: VALID
//	OrganizationClaim      IsExpired = now.After(ExpiresAt)   -> at ExpiresAt: VALID
//	EmailVerification      IsValid   = now.Before(ExpiresAt)  -> at ExpiresAt: INVALID
//
// Three inclusive, one exclusive. Nothing declares that asymmetry deliberate, and
// nothing but a frozen clock can hold it still long enough to be looked at. These
// tests record the behaviour as it is; if the divergence is a bug, they are what
// makes changing it a visible decision rather than an invisible drift.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// seamEpoch is deliberately far from any plausible wall clock. If an injection is
// removed, the service compares a 2031 ExpiresAt against today and the assertion
// fails loudly instead of drifting into a date-dependent pass.
var seamEpoch = time.Date(2031, 3, 1, 12, 0, 0, 0, time.UTC)

// stepClock is a clock that only moves when a test moves it.
type stepClock struct{ at time.Time }

func newStepClock() *stepClock               { return &stepClock{at: seamEpoch} }
func (c *stepClock) Now() time.Time          { return c.at }
func (c *stepClock) set(t time.Time)         { c.at = t }
func (c *stepClock) advance(d time.Duration) { c.at = c.at.Add(d) }

// TestPasswordResetSeam_ValidExactlyAtExpiry pins PasswordResetServiceConfig.Now.
// IsExpired is `now.After(ExpiresAt)`, so the deadline instant itself is still
// usable — an inclusive boundary that only a stopped clock can stand on.
func TestPasswordResetSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	user := newPasswordResetUser(t, "seam-reset@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:    users,
		Resets:   resets,
		Notifier: &fakePasswordResetNotifier{},
		Audit:    audit.NoopService{},
		TTL:      time.Hour,
		Now:      clock.Now,
	})

	require.NoError(t, svc.RequestPasswordReset(context.Background(), user.Email, "10.0.0.1", "seam-test"))
	require.Len(t, resets.rows, 1, "one reset row persisted")
	var row *domain.PasswordReset
	for _, r := range resets.rows {
		row = r
	}
	require.NotNil(t, row)

	// The row was minted from the frozen clock, so its deadline is exact.
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), row.ExpiresAt.UTC(),
		"ExpiresAt must come from the injected clock, not the wall clock")

	// Stand exactly on the deadline.
	clock.set(row.ExpiresAt)
	assert.False(t, row.IsExpired(clock.Now()),
		"at ExpiresAt exactly, IsExpired is now.After(ExpiresAt) = false — the token is still live")
	assert.True(t, row.IsValid(clock.Now()),
		"an unused token at its exact deadline is still valid")

	// One nanosecond later it is not.
	clock.advance(time.Nanosecond)
	assert.True(t, row.IsExpired(clock.Now()), "one nanosecond past the deadline expires it")
}

// TestEmailVerificationSeam_InvalidExactlyAtExpiry pins
// EmailVerificationServiceOptions.Now — and the ONE boundary of the four that is
// exclusive. IsValid is `now.Before(ExpiresAt)`, so the deadline instant is
// already too late here while the other three still accept it.
func TestEmailVerificationSeam_InvalidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	user := newPasswordResetUser(t, "seam-verify@example.test")
	user.EmailVerified = false
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{},
		EmailVerificationServiceOptions{TTL: time.Hour, Now: clock.Now})

	_, err := svc.IssueInitialVerification(context.Background(), user)
	require.NoError(t, err)
	require.Len(t, verifs.rows, 1)
	var row *domain.EmailVerification
	for _, r := range verifs.rows {
		row = r
	}
	require.NotNil(t, row)
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), row.ExpiresAt.UTC(),
		"ExpiresAt must come from the injected clock, not the wall clock")

	// One nanosecond BEFORE the deadline it is still valid.
	clock.set(row.ExpiresAt.Add(-time.Nanosecond))
	assert.True(t, row.IsValid(clock.Now()), "a nanosecond before the deadline is still valid")

	// Exactly ON the deadline it is NOT — this is the asymmetry with the other three.
	clock.set(row.ExpiresAt)
	assert.False(t, row.IsValid(clock.Now()),
		"at ExpiresAt exactly, IsValid is now.Before(ExpiresAt) = false — EXCLUSIVE, unlike PasswordReset/Activation/Claim")
}

// TestActivationSeam_ValidExactlyAtExpiry pins
// OrganizationActivationServiceConfig.Now. The service expires a token with
// `s.now().After(*user.ActivationTokenExpiresAt)`, so the deadline instant is
// still accepted.
func TestActivationSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "Acme", Domain: "acme.test", OrgSlug: "acme"}
	id, err := uuid.NewV7()
	require.NoError(t, err)
	user := &domain.User{
		ID:             id,
		OrganizationID: orgID,
		Email:          "seam-admin@acme.test",
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
	}
	users := newFakeUserRepo(user)
	orgs := newFakeOrgRepo(org)
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users:     users,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Audit:     audit.NoopService{},
		TTL:       time.Hour,
		Now:       clock.Now,
	})

	raw, expiresAt, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), expiresAt.UTC(),
		"the returned deadline must come from the injected clock, not the wall clock")

	// Exactly on the deadline the token still validates.
	clock.set(expiresAt)
	res, err := svc.ValidateActivationToken(context.Background(), raw)
	require.NoError(t, err, "at ExpiresAt exactly, expiry is now.After(ExpiresAt) = false — still valid")
	require.NotNil(t, res)

	// One nanosecond later it does not.
	clock.advance(time.Nanosecond)
	_, err = svc.ValidateActivationToken(context.Background(), raw)
	assert.Error(t, err, "one nanosecond past the deadline must be refused")
}

// TestClaimSeam_ValidExactlyAtExpiry pins ClaimServiceConfig.Now. IsExpired is
// `now.After(ExpiresAt)`, so the deadline instant is still claimable.
func TestClaimSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "Acme", Domain: "acme.test", OrgSlug: "acme", Active: false}
	claims := newFakeClaimRepo()
	orgs := newFakeOrgRepo(org)
	users := newFakeUserRepo()
	svc := NewClaimService(ClaimServiceConfig{
		Claims:    claims,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Users:     users,
		Exists:    users,
		Audit:     audit.NoopService{},
		TTL:       time.Hour,
		Now:       clock.Now,
	})

	raw, expiresAt, err := svc.GenerateClaimToken(context.Background(), orgID, "seam-claim@acme.test")
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), expiresAt.UTC(),
		"the returned deadline must come from the injected clock, not the wall clock")

	// ValidateClaim is ORACLE-HARDENED: every failure mode returns
	// {Valid:false}, nil so the wire cannot distinguish bad-token from expired.
	// The boundary therefore shows up in the FLAG, never in an error — asserting
	// on err here would pass at both instants and prove nothing.
	clock.set(expiresAt)
	res, err := svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Valid, "at ExpiresAt exactly, IsExpired is now.After(ExpiresAt) = false — still claimable")

	// One nanosecond later it is not.
	clock.advance(time.Nanosecond)
	res, err = svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.Valid, "one nanosecond past the deadline must be refused")
}
