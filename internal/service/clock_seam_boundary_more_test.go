package service

// clock_seam_boundary_more_test.go — boundary tests for clock seams whose
// deadline instant nothing had ever stood on (TWENTY-DEADLINES, 2026-08-02).
//
// THE OPERATORS DO NOT AGREE AT THE INSTANT, which is why each of these needs
// its own assertion rather than a shared helper:
//
//	OIDCDiscoveryService   cache HIT iff now.Before(expiry)  -> at expiry: MISS
//	ServiceAccountService  rejected iff !ExpiresAt.After(now) -> at expiry: REJECTED
//
// Both are EXCLUSIVE at the instant — the opposite of PasswordReset, Claim and
// Activation, which accept it. Copying one of those tests would have produced a
// wrong assertion here, and copying these into those would be wrong the other way.
//
// EACH ASSIGNS THE PRIVATE `now` FIELD DIRECTLY. Neither constructor takes a
// clock, so the seam is reachable only from inside this package — which is
// exactly why no out-of-package test could ever have pinned these boundaries.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TestOIDCDiscoverySeam_CacheMissExactlyAtExpiry pins OIDCDiscoveryService.now.
// The cache is consulted with `now.Before(e.expiry)`, so the expiry instant is
// ALREADY a miss — exclusive, unlike the token services in this same package.
func TestOIDCDiscoverySeam_CacheMissExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	svc := NewOIDCDiscoveryService(OIDCDiscoveryOptions{})
	svc.now = clock.Now

	const issuer = "https://idp.example.test"
	expiry := seamEpoch.Add(time.Hour)
	svc.mu.Lock()
	svc.cache[issuer] = &oidcDiscoveryEntry{
		doc:    &OIDCDiscoveryDocument{Issuer: issuer},
		expiry: expiry,
	}
	svc.mu.Unlock()

	// One nanosecond BEFORE the expiry the cached document is returned.
	clock.set(expiry.Add(-time.Nanosecond))
	got, err := svc.Discover(context.Background(), issuer)
	require.NoError(t, err, "a nanosecond before expiry the cache must still hit")
	require.NotNil(t, got)
	assert.Equal(t, issuer, got.Issuer)

	// EXACTLY at the expiry it is not: `now.Before(expiry)` is false, so the
	// service falls through to a network fetch, which fails in this fixture.
	clock.set(expiry)
	_, err = svc.Discover(context.Background(), issuer)
	assert.Error(t, err,
		"at expiry exactly, the cache check is now.Before(expiry) = false — EXCLUSIVE, so this must miss")
}

// TestServiceAccountSeam_RejectedExactlyAtExpiry pins ServiceAccountService.now.
// A requested expiry is rejected when `!in.ExpiresAt.After(s.now())`, so an
// expiry equal to now is ALREADY invalid.
func TestServiceAccountSeam_RejectedExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	svc := NewServiceAccountService(nil, nil)
	svc.now = clock.Now

	orgID := uuid.New()
	actor := &domain.Principal{OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	at := seamEpoch
	clock.set(at)

	// EXACTLY now: `!at.After(now)` is true, so this is refused.
	_, err := svc.buildForActor(actor, orgID, ServiceAccountAdminInput{
		Name:      "sa-at-boundary",
		ExpiresAt: &at,
	})
	assert.ErrorIs(t, err, ErrSAExpiryInvalid,
		"an expiry equal to now is rejected: the guard is !ExpiresAt.After(now) — EXCLUSIVE")

	// One nanosecond later it is accepted.
	later := at.Add(time.Nanosecond)
	_, err = svc.buildForActor(actor, orgID, ServiceAccountAdminInput{
		Name:      "sa-past-boundary",
		ExpiresAt: &later,
	})
	assert.NotErrorIs(t, err, ErrSAExpiryInvalid,
		"one nanosecond past now is a valid expiry")
}

// ---------- fakes for the seams whose services take a repository ----------

// fakeOrgDomainRepoSeam is the narrow slice of OrganizationDomainRepository that
// Verify() touches. Every other method returns an error so a future caller that
// wanders in fails loudly rather than getting a plausible zero value.
type fakeOrgDomainRepoSeam struct {
	row      *domain.OrganizationDomain
	verified bool
}

func (f *fakeOrgDomainRepoSeam) CreateOrganizationDomain(context.Context, *domain.OrganizationDomain) (*domain.OrganizationDomain, error) {
	return nil, errSeamFakeUnimplemented
}

func (f *fakeOrgDomainRepoSeam) GetOrganizationDomainByID(context.Context, uuid.UUID) (*domain.OrganizationDomain, error) {
	return f.row, nil
}

func (f *fakeOrgDomainRepoSeam) ListOrganizationDomainsByOrganization(context.Context, uuid.UUID) ([]*domain.OrganizationDomain, error) {
	return nil, errSeamFakeUnimplemented
}

func (f *fakeOrgDomainRepoSeam) GetVerifiedOrganizationDomainByDomain(context.Context, string) (*domain.OrganizationDomain, error) {
	return nil, errSeamFakeUnimplemented
}

func (f *fakeOrgDomainRepoSeam) SetOrganizationDomainVerified(context.Context, uuid.UUID, time.Time) error {
	f.verified = true
	return nil
}

func (f *fakeOrgDomainRepoSeam) IncrementOrganizationDomainVerificationAttempts(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func (f *fakeOrgDomainRepoSeam) DeleteOrganizationDomain(context.Context, uuid.UUID, uuid.UUID) error {
	return errSeamFakeUnimplemented
}

func (f *fakeOrgDomainRepoSeam) SetPrimaryOrganizationDomain(context.Context, uuid.UUID, uuid.UUID) error {
	return errSeamFakeUnimplemented
}

// okDomainVerifier accepts any proof, so the only thing that can refuse the
// verification in the test below is the deadline.
type okDomainVerifier struct{}

func (okDomainVerifier) Verify(context.Context, string, string) error { return nil }

var errSeamFakeUnimplemented = errors.New("seam fake: method not implemented on purpose")

// TestOrganizationDomainSeam_ValidExactlyAtExpiry pins
// OrganizationDomainService.now — the ONE seam in the fleet whose operands are
// REVERSED. Every other deadline asks `now.After(deadline)`; this asks
// `deadline.Before(now)`. The two are equivalent, which is precisely why the
// reversal survives review unnoticed, and why the boundary is worth pinning.
func TestOrganizationDomainSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	hash := "abc123"
	expiry := seamEpoch.Add(time.Hour)
	orgID := uuid.New()
	id := uuid.New()
	repo := &fakeOrgDomainRepoSeam{row: &domain.OrganizationDomain{
		ID:                         id,
		OrganizationID:             orgID,
		Domain:                     "acme.test",
		VerificationTokenHash:      &hash,
		VerificationTokenExpiresAt: &expiry,
	}}
	svc := NewOrganizationDomainService(nil, repo, okDomainVerifier{})
	svc.now = clock.Now

	// EXACTLY at the deadline: `ExpiresAt.Before(now)` is false, so NOT expired.
	clock.set(expiry)
	err := svc.Verify(context.Background(), id, orgID)
	assert.NotErrorIs(t, err, ErrDomainTokenExpired,
		"at ExpiresAt exactly, expiry is ExpiresAt.Before(now) = false — the token is still live")
	assert.True(t, repo.verified, "the verification completed at the deadline instant")

	// One nanosecond later it is expired.
	repo.row.VerifiedAt = nil
	repo.verified = false
	clock.set(expiry.Add(time.Nanosecond))
	err = svc.Verify(context.Background(), id, orgID)
	assert.ErrorIs(t, err, ErrDomainTokenExpired,
		"one nanosecond past the deadline must be refused")
}

// ---------- the four PRIVATE fields behind the four Config seams ----------
//
// clock_seam_boundary_test.go pins these boundaries through the exported Config
// seam. These four pin the PRIVATE field the comparison actually reads. That is
// not a duplicate assertion: the Config test proves the option FLOWS IN, and
// these prove the field is what the deadline check CONSULTS. A constructor that
// stored the clock somewhere else would pass the first and fail these.

// TestPasswordResetPrivateSeam_ValidExactlyAtExpiry — IsExpired = now.After(exp).
func TestPasswordResetPrivateSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	user := newPasswordResetUser(t, "priv-reset@example.test")
	resets := newFakePasswordResetRepo()
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users: newFakeUserRepo(user), Resets: resets,
		Notifier: &fakePasswordResetNotifier{}, Audit: audit.NoopService{}, TTL: time.Hour,
	})
	svc.now = clock.Now // the seam under test — NOT supplied through the config

	require.NoError(t, svc.RequestPasswordReset(context.Background(), user.Email, "10.0.0.1", "seam"))
	require.Len(t, resets.rows, 1)
	var row *domain.PasswordReset
	for _, r := range resets.rows {
		row = r
	}
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), row.ExpiresAt.UTC(),
		"the private field must be what mints ExpiresAt")
	clock.set(row.ExpiresAt)
	assert.False(t, row.IsExpired(clock.Now()), "at ExpiresAt exactly: now.After(exp) = false — VALID")
	clock.advance(time.Nanosecond)
	assert.True(t, row.IsExpired(clock.Now()))
}

// TestEmailVerificationPrivateSeam_InvalidExactlyAtExpiry — IsValid = now.Before(exp).
func TestEmailVerificationPrivateSeam_InvalidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	user := newPasswordResetUser(t, "priv-verify@example.test")
	user.EmailVerified = false
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, nil, audit.NoopService{},
		EmailVerificationServiceOptions{TTL: time.Hour})
	svc.now = clock.Now

	_, err := svc.IssueInitialVerification(context.Background(), user)
	require.NoError(t, err)
	require.Len(t, verifs.rows, 1)
	var row *domain.EmailVerification
	for _, r := range verifs.rows {
		row = r
	}
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), row.ExpiresAt.UTC())
	clock.set(row.ExpiresAt.Add(-time.Nanosecond))
	assert.True(t, row.IsValid(clock.Now()))
	clock.set(row.ExpiresAt)
	assert.False(t, row.IsValid(clock.Now()),
		"at ExpiresAt exactly: now.Before(exp) = false — INVALID, unlike the other three")
}

// TestActivationPrivateSeam_ValidExactlyAtExpiry — expired iff now.After(*exp).
func TestActivationPrivateSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "Acme", Domain: "acme.test", OrgSlug: "acme"}
	id, err := uuid.NewV7()
	require.NoError(t, err)
	user := &domain.User{ID: id, OrganizationID: orgID, Email: "priv-admin@acme.test",
		Role: domain.RoleOrgAdmin, AuthSource: domain.AuthSourceLocal}
	orgs := newFakeOrgRepo(org)
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: newFakeUserRepo(user), Orgs: orgs, OrgsAdmin: orgs,
		Audit: audit.NoopService{}, TTL: time.Hour,
	})
	svc.now = clock.Now

	raw, expiresAt, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), expiresAt.UTC())
	clock.set(expiresAt)
	_, err = svc.ValidateActivationToken(context.Background(), raw)
	require.NoError(t, err, "at ExpiresAt exactly: now.After(exp) = false — VALID")
	clock.advance(time.Nanosecond)
	_, err = svc.ValidateActivationToken(context.Background(), raw)
	assert.Error(t, err)
}

// TestClaimPrivateSeam_ValidExactlyAtExpiry — IsExpired = now.After(exp).
// ValidateClaim is oracle-hardened, so the boundary shows in the FLAG, never an error.
func TestClaimPrivateSeam_ValidExactlyAtExpiry(t *testing.T) {
	clock := newStepClock()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "Acme", Domain: "acme.test", OrgSlug: "acme"}
	orgs := newFakeOrgRepo(org)
	users := newFakeUserRepo()
	svc := NewClaimService(ClaimServiceConfig{
		Claims: newFakeClaimRepo(), Orgs: orgs, OrgsAdmin: orgs, Users: users, Exists: users,
		Audit: audit.NoopService{}, TTL: time.Hour,
	})
	svc.now = clock.Now

	raw, expiresAt, err := svc.GenerateClaimToken(context.Background(), orgID, "priv-claim@acme.test")
	require.NoError(t, err)
	require.Equal(t, seamEpoch.Add(time.Hour).UTC(), expiresAt.UTC())
	clock.set(expiresAt)
	res, err := svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	assert.True(t, res.Valid, "at ExpiresAt exactly: now.After(exp) = false — still claimable")
	clock.advance(time.Nanosecond)
	res, err = svc.ValidateClaim(context.Background(), raw)
	require.NoError(t, err)
	assert.False(t, res.Valid)
}

// TestClientAssertionSeam_ValidExactlyAtExpiryPlusSkew pins
// ClientAssertionValidator.now. The guard is `now.After(exp.Add(ClockSkew))`, so
// the instant exp+skew is still ACCEPTED — the tolerance is inclusive at its far
// edge, which no wall-clock test can stand on.
func TestClientAssertionSeam_ValidExactlyAtExpiryPlusSkew(t *testing.T) {
	clock := newStepClock()
	v := newAssertionValidator(t)
	v.now = clock.Now

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	const kid = "seam-kid"
	client := newJWKSClient(t, "seam-client", kid, pub)

	exp := seamEpoch.Add(time.Minute)
	claims := jwt.MapClaims{
		"iss": "seam-client",
		"sub": "seam-client",
		"aud": "https://idp.test/api/v1/oauth/token",
		"exp": exp.Unix(),
		"iat": seamEpoch.Unix(),
		"jti": "jti-" + uuid.NewString(),
	}
	assertion := signEdDSAAssertion(t, priv, kid, claims)

	// EXACTLY at exp+skew: `now.After(exp+skew)` is false — still accepted.
	clock.set(exp.Add(v.cfg.ClockSkew))
	_, err = v.Validate(context.Background(), client, assertion)
	require.NoError(t, err, "at exp+ClockSkew exactly the assertion is still valid — INCLUSIVE")

	// One second later it is not (exp is second-granular in a JWT).
	clock.set(exp.Add(v.cfg.ClockSkew).Add(time.Second))
	_, err = v.Validate(context.Background(), client, assertion)
	assert.Error(t, err, "past exp+ClockSkew the assertion must be refused")
}

// TestUserSessionSeam_ExpiredExactlyAtAbsoluteLifetime pins
// UserSessionService.now. The guard is `now.Sub(CreatedAt) >= absoluteLifetime`,
// so the lifetime instant is ALREADY over — `>=` makes this the only inclusive-
// EXPIRED boundary in the repo, the mirror image of the token services.
func TestUserSessionSeam_ExpiredExactlyAtAbsoluteLifetime(t *testing.T) {
	clock := newStepClock()
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{
		DefaultTTL:       24 * time.Hour,
		AbsoluteLifetime: time.Hour,
	})
	svc.now = clock.Now

	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.Equal(t, seamEpoch.UTC(), issued.Session.CreatedAt.UTC(),
		"CreatedAt must come from the injected clock")

	// One nanosecond BEFORE the absolute lifetime: rotation still allowed.
	clock.set(seamEpoch.Add(time.Hour - time.Nanosecond))
	_, err = svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
	require.NoError(t, err, "a nanosecond before the absolute lifetime rotation is allowed")

	// EXACTLY at the absolute lifetime: `>=` is true, so the session is done.
	clock.set(seamEpoch.Add(time.Hour))
	_, err = svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
	assert.ErrorIs(t, err, ErrUserSessionInvalidGrant,
		"at CreatedAt+AbsoluteLifetime exactly the guard is >= — EXPIRED, not valid")
}

// TestOIDCCallbackSeam_ValidExactlyAtStateExpiry pins OIDCCallbackService.now.
// The consumed state row is refused when `s.now().After(st.ExpiresAt)`, so the
// expiry instant itself is still ACCEPTED — inclusive, and the existing
// "expired state" test can only ever sit a minute past it.
func TestOIDCCallbackSeam_ValidExactlyAtStateExpiry(t *testing.T) {
	clock := newStepClock()
	h := newCallbackHarness(t)
	// Bound to a local so the receiver's type is resolvable: `h.svc.now = ...`
	// is a selector expression, which tools/clockfuse cannot attribute and which
	// would therefore shadow every other `now` seam in this package.
	svc := h.svc
	svc.now = clock.Now

	expiry := seamEpoch.Add(time.Hour)
	h.states.byState[h.stateKey].ExpiresAt = expiry
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())

	// EXACTLY at the deadline: `now.After(exp)` is false, so the state is NOT
	// rejected. The call proceeds past the expiry gate; whatever it fails on
	// later, it must not be ErrCallbackStateInvalid.
	clock.set(expiry)
	_, err := h.call()
	assert.NotErrorIs(t, err, ErrCallbackStateInvalid,
		"at ExpiresAt exactly: now.After(exp) = false — the state is still usable")

	// One nanosecond later the same state IS rejected.
	h2 := newCallbackHarness(t)
	svc2 := h2.svc
	svc2.now = clock.Now
	h2.states.byState[h2.stateKey].ExpiresAt = expiry
	*h2.idToken = h2.signEdDSA(t, h2.priv, h2.kid, h2.validClaims())
	clock.set(expiry.Add(time.Nanosecond))
	_, err = h2.call()
	assert.ErrorIs(t, err, ErrCallbackStateInvalid,
		"one nanosecond past the state deadline must be refused")
}
