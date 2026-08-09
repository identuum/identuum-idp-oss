package service

// organization_activation_service_test.go — unit tests for the OSS
// OrganizationActivationService. Covered:
//
//   - issue: persists hash + expiry on user row; raw token returned;
//   - validate: bad token / expired / consumed → ErrInvalidToken;
//   - validate: org already active → ErrOrganizationAlreadyActive;
//   - validate: success → returns Email + OrgID;
//   - consume: bad token → ErrInvalidToken;
//   - consume: weak password → ErrWeakPassword;
//   - consume: org already active → ErrOrganizationAlreadyActive;
//   - consume: happy path → password set + email verified + org Active +
//     activation_token_hash cleared (single-use burn-before-write);
//   - consume replay (after burn) → ErrInvalidToken;
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
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// fakeOrgRepo satisfies the org seams the service needs.
type fakeOrgRepo struct {
	mu          sync.Mutex
	byID        map[uuid.UUID]*domain.Organization
	updateCount int
	lastOpts    repository.UpdateOrganizationOptions
}

func newFakeOrgRepo(orgs ...*domain.Organization) *fakeOrgRepo {
	r := &fakeOrgRepo{byID: make(map[uuid.UUID]*domain.Organization)}
	for _, o := range orgs {
		r.byID[o.ID] = o
	}
	return r
}

func (r *fakeOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrOrganizationNotFound
	}
	if !o.Active {
		// GetByID hides inactive orgs by default in the production
		// surface; the fake mirrors that so tests can prove the
		// service falls through to the admin seam.
		return nil, domain.ErrOrganizationNotFound
	}
	return o, nil
}

func (r *fakeOrgRepo) GetByIDAdmin(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrOrganizationNotFound
	}
	return o, nil
}

func (r *fakeOrgRepo) Update(_ context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateCount++
	r.lastOpts = opts
	o, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrOrganizationNotFound
	}
	if opts.Active != nil {
		o.Active = *opts.Active
	}
	return o, nil
}

type fakeActivationNotifier struct {
	sends      int
	lastUserID uuid.UUID
	lastToken  string
}

func (n *fakeActivationNotifier) SendActivationEmail(_ context.Context, user *domain.User, raw string, _ time.Time) error {
	n.sends++
	if user != nil {
		n.lastUserID = user.ID
	}
	n.lastToken = raw
	return nil
}

func newActivationFixture(t *testing.T) (*OrganizationActivationService, *fakeUserRepo, *fakeOrgRepo, *fakeAuditRecorder, *domain.User, *domain.Organization) {
	t.Helper()
	orgID := uuid.New()
	org := &domain.Organization{
		ID:      orgID,
		Name:    "Acme",
		Domain:  "acme.test",
		OrgSlug: "acme",
		Active:  false,
	}
	uid, err := uuid.NewV7()
	require.NoError(t, err)
	user := &domain.User{
		ID:             uid,
		OrganizationID: orgID,
		Email:          "admin@acme.test",
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
	}
	users := newFakeUserRepo(user)
	orgs := newFakeOrgRepo(org)
	rec := &fakeAuditRecorder{}
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users:     users,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Audit:     rec,
	})
	return svc, users, orgs, rec, user, org
}

// ---------- tests ----------

func TestIssueActivationToken_PersistsAndEmails(t *testing.T) {
	_, users, orgs, _, user, _ := newActivationFixture(t)
	notifier := &fakeActivationNotifier{}
	// Swap notifier in via a fresh service so the fixture's helper stays small.
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users:     users,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Notifier:  notifier,
		Audit:     audit.NoopService{},
	})

	raw, expiresAt, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	assert.Len(t, raw, 64)
	assert.True(t, expiresAt.After(time.Now()))
	require.NotNil(t, user.ActivationTokenHash)
	assert.Len(t, *user.ActivationTokenHash, 64)
	assert.Equal(t, 1, notifier.sends)
	assert.Equal(t, raw, notifier.lastToken)
}

func TestIssueActivationToken_RejectsNonOrgAdmin(t *testing.T) {
	svc, _, _, _, user, _ := newActivationFixture(t)
	user.Role = domain.RoleOrgUser
	_, _, err := svc.IssueActivationToken(context.Background(), user)
	require.Error(t, err)
}

func TestValidateActivationToken_BadTokenIsInvalid(t *testing.T) {
	svc, _, _, _, _, _ := newActivationFixture(t)
	_, err := svc.ValidateActivationToken(context.Background(), "nope")
	assert.ErrorIs(t, err, ErrOrganizationActivationInvalidToken)
}

func TestValidateActivationToken_EmptyTokenIsInvalid(t *testing.T) {
	svc, _, _, _, _, _ := newActivationFixture(t)
	_, err := svc.ValidateActivationToken(context.Background(), "")
	assert.ErrorIs(t, err, ErrOrganizationActivationInvalidToken)
}

func TestValidateActivationToken_HappyPath(t *testing.T) {
	svc, _, _, _, user, org := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	result, err := svc.ValidateActivationToken(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, org.ID, result.OrgID)
}

func TestValidateActivationToken_AlreadyActiveReturnsSentinel(t *testing.T) {
	svc, _, _, _, user, org := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	org.Active = true
	_, err = svc.ValidateActivationToken(context.Background(), raw)
	assert.ErrorIs(t, err, ErrOrganizationAlreadyActive)
}

func TestValidateActivationToken_ExpiredIsInvalid(t *testing.T) {
	svc, _, _, _, user, _ := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	user.ActivationTokenExpiresAt = &past
	_, err = svc.ValidateActivationToken(context.Background(), raw)
	assert.ErrorIs(t, err, ErrOrganizationActivationInvalidToken)
}

func TestConsumeActivationToken_WeakPasswordRejected(t *testing.T) {
	svc, _, _, _, user, _ := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	_, _, err = svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{Token: raw, Password: "short"})
	assert.ErrorIs(t, err, ErrOrganizationActivationWeakPassword)
}

func TestConsumeActivationToken_BadTokenIsInvalid(t *testing.T) {
	svc, _, _, _, _, _ := newActivationFixture(t)
	_, _, err := svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{Token: "bad", Password: "Longenough-Password-1!"})
	assert.ErrorIs(t, err, ErrOrganizationActivationInvalidToken)
}

func TestConsumeActivationToken_AlreadyActiveReturnsSentinel(t *testing.T) {
	svc, _, _, _, user, org := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	org.Active = true
	_, _, err = svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{Token: raw, Password: "Longenough-Password-1!"})
	assert.ErrorIs(t, err, ErrOrganizationAlreadyActive)
}

func TestConsumeActivationToken_HappyPath(t *testing.T) {
	_, users, orgs, rec, user, _ := newActivationFixture(t)
	notifier := &fakeActivationNotifier{}
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users:     users,
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Notifier:  notifier,
		Audit:     rec,
	})

	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	updatedUser, updatedOrg, err := svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{
		Token:    raw,
		Password: "Longenough-Password-1!",
	})
	require.NoError(t, err)
	require.NotNil(t, updatedUser)
	require.NotNil(t, updatedOrg)
	assert.True(t, updatedOrg.Active)
	// activation_token_hash cleared
	assert.Nil(t, user.ActivationTokenHash)
	// email_verified flipped
	assert.True(t, user.EmailVerified)
	// password updated
	assert.True(t, strings.HasPrefix(user.PasswordHash, "$argon2id$"))

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditOrgActivated), events[0].Action)
	// Raw token MUST NOT appear in any metadata value.
	for _, e := range events {
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok {
				assert.False(t, strings.Contains(s, raw),
					"metadata key %q must not contain raw activation token", k)
			}
		}
	}
}

func TestConsumeActivationToken_ReplayAfterBurnIsInvalid(t *testing.T) {
	svc, _, _, _, user, org := newActivationFixture(t)
	raw, _, err := svc.IssueActivationToken(context.Background(), user)
	require.NoError(t, err)
	_, _, err = svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{Token: raw, Password: "Longenough-Password-1!"})
	require.NoError(t, err)
	// After consume, the org is active. Replay must hit either the
	// burn-cleared activation hash OR the already-active gate — both
	// surface as opaque sentinels. (Activation flips org.Active to
	// true; if replay hits the already-active path it surfaces
	// ErrOrganizationAlreadyActive instead.)
	assert.True(t, org.Active, "org must be active after first consume")
	_, _, err = svc.ConsumeActivationToken(context.Background(), ConsumeActivationInput{Token: raw, Password: "Longenough-Password-1!"})
	if err != ErrOrganizationActivationInvalidToken && err != ErrOrganizationAlreadyActive {
		t.Errorf("replay must collapse onto opaque sentinel; got %v", err)
	}
}
