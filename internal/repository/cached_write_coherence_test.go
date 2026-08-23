package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Updating or deleting a user, organization, or service account evicts its
// cached entries, so a mutated or deleted entity's stale snapshot is never
// served — the next read consults the database. Every path seeds THROUGH the
// public read (miss → delegate → cached; the second read is a proven hit
// against a .Once delegate expectation), so each assertion is about what the
// SERVING path returns, not which keys exist.
// RULE: CACHE-WRITE-INVALIDATE-1
func TestCachedRepositories_StaleWriteNeverServedFromCache(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()
	ctx := context.Background()

	// ---- User layer ----
	userMock := new(MockUserRepository)
	users := NewCachedUserRepository(userMock, rdb, 5*time.Minute)
	orgU := uuid.New()
	u := &domain.User{ID: uuid.New(), OrganizationID: orgU, Email: "write-coherence@example.test"}

	userMock.On("GetByID", ctx, u.ID).Return(u, nil).Once()
	got, err := users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, u.Email, got.Email)
	got, err = users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, u.Email, got.Email)

	renamed := *u
	renamed.Email = "renamed@example.test"
	userMock.On("GetByID", ctx, u.ID).Return(u, nil).Once() // Update's pre-fetch
	userMock.On("Update", ctx, u.ID, orgU, mock.Anything).Return(&renamed, nil).Once()
	_, err = users.Update(ctx, u.ID, orgU, UpdateUserOptions{})
	require.NoError(t, err)

	userMock.On("GetByID", ctx, u.ID).Return(&renamed, nil).Once()
	got, err = users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "renamed@example.test", got.Email,
		"updated user must not be served from cache: stale snapshot returned after Update")

	userMock.On("GetByID", ctx, u.ID).Return(&renamed, nil).Once() // Delete's pre-fetch
	userMock.On("Delete", ctx, u.ID, orgU).Return(nil).Once()
	require.NoError(t, users.Delete(ctx, u.ID, orgU))

	userMock.On("GetByID", ctx, u.ID).
		Return((*domain.User)(nil), fmt.Errorf("user deleted")).Once()
	_, err = users.GetByID(ctx, u.ID)
	assert.Error(t, err, "deleted user must not be served from cache")
	userMock.AssertExpectations(t)

	// ---- Organization layer ----
	orgMock := new(MockOrganizationRepository)
	orgs := NewCachedOrganizationRepository(orgMock, rdb, 5*time.Minute)
	o := &domain.Organization{ID: uuid.New(), Name: "before-rename"}

	orgMock.On("GetByID", ctx, o.ID).Return(o, nil).Once()
	gotOrg, err := orgs.GetByID(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, "before-rename", gotOrg.Name)
	gotOrg, err = orgs.GetByID(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, "before-rename", gotOrg.Name)

	renamedOrg := *o
	renamedOrg.Name = "after-rename"
	orgMock.On("GetByID", ctx, o.ID).Return(o, nil).Once() // Update's pre-fetch
	orgMock.On("Update", ctx, o.ID, mock.Anything).Return(&renamedOrg, nil).Once()
	_, err = orgs.Update(ctx, o.ID, UpdateOrganizationOptions{})
	require.NoError(t, err)

	orgMock.On("GetByID", ctx, o.ID).Return(&renamedOrg, nil).Once()
	gotOrg, err = orgs.GetByID(ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, "after-rename", gotOrg.Name,
		"updated organization must not be served from cache: stale snapshot returned after Update")

	orgMock.On("GetByID", ctx, o.ID).Return(&renamedOrg, nil).Once() // Delete's pre-fetch
	orgMock.On("Delete", ctx, o.ID).Return(nil).Once()
	require.NoError(t, orgs.Delete(ctx, o.ID))

	orgMock.On("GetByID", ctx, o.ID).
		Return((*domain.Organization)(nil), fmt.Errorf("organization deleted")).Once()
	_, err = orgs.GetByID(ctx, o.ID)
	assert.Error(t, err, "deleted organization must not be served from cache")
	orgMock.AssertExpectations(t)

	// ---- Service-account layer ----
	saMock := new(mockServiceAccountRepository)
	sas := NewCachedServiceAccountRepository(saMock, rdb, 5*time.Minute)
	orgSA := uuid.New()
	sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: orgSA, Name: "before-sa"}

	saMock.On("GetByID", ctx, sa.ID).Return(sa, nil).Once()
	gotSA, err := sas.GetByID(ctx, sa.ID)
	require.NoError(t, err)
	require.Equal(t, "before-sa", gotSA.Name)
	gotSA, err = sas.GetByID(ctx, sa.ID)
	require.NoError(t, err)
	require.Equal(t, "before-sa", gotSA.Name)

	renamedSA := *sa
	renamedSA.Name = "after-sa"
	saMock.On("Update", ctx, mock.Anything).Return(&renamedSA, nil).Once()
	_, err = sas.Update(ctx, sa)
	require.NoError(t, err)

	saMock.On("GetByID", ctx, sa.ID).Return(&renamedSA, nil).Once()
	gotSA, err = sas.GetByID(ctx, sa.ID)
	require.NoError(t, err)
	assert.Equal(t, "after-sa", gotSA.Name,
		"updated service account must not be served from cache: stale snapshot returned after Update")

	saMock.On("GetByID", ctx, sa.ID).Return(&renamedSA, nil).Once() // Delete's pre-fetch
	saMock.On("Delete", ctx, sa.ID, orgSA).Return(nil).Once()
	require.NoError(t, sas.Delete(ctx, sa.ID, orgSA))

	saMock.On("GetByID", ctx, sa.ID).
		Return((*domain.ServiceAccount)(nil), fmt.Errorf("service account deleted")).Once()
	_, err = sas.GetByID(ctx, sa.ID)
	assert.Error(t, err, "deleted service account must not be served from cache")
	saMock.AssertExpectations(t)
}

// rotateSessionRepository overrides the shared mock's stub RotateToken so the
// rotation can report won=true through testify expectations.
type rotateSessionRepository struct {
	MockSessionRepository
}

func (m *rotateSessionRepository) RotateToken(ctx context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	args := m.Called(ctx, sessionID, expectedValidatorHash, newValidatorHash, newExpiresAt, lastUsedAt)
	var s *domain.Session
	if a := args.Get(0); a != nil {
		s = a.(*domain.Session)
	}
	return s, args.Bool(1), args.Error(2)
}

// A successful session rotation evicts the cached validation snapshot — the
// next validation consults the database — and the session-by-id read is never
// served from a cache at all: two consecutive by-id reads both reach the
// database.
// RULE: SESSION-CACHE-ROTATE-1
func TestCachedSessionRepository_RotationEvictsAndByIDNeverCached(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()
	ctx := context.Background()

	mockRepo := new(rotateSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rdb)

	// Rotation clause: seed the validation snapshot through the public read
	// with a proven cache hit, rotate with won=true, then the next validation
	// must consult the database.
	s := &domain.Session{ID: uuid.New(), UserID: uuid.New()}
	info := &domain.SessionValidationInfo{Session: s}
	mockRepo.On("GetSessionWithUserAndOrgStatus", ctx, s.ID).Return(info, nil).Once()
	gotInfo, err := repo.GetSessionWithUserAndOrgStatus(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, s.ID, gotInfo.Session.ID)
	gotInfo, err = repo.GetSessionWithUserAndOrgStatus(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, s.ID, gotInfo.Session.ID)

	exp := time.Now().Add(time.Hour)
	used := time.Now()
	mockRepo.On("RotateToken", ctx, s.ID, "old-hash", "new-hash", exp, used).
		Return(s, true, nil).Once()
	_, won, err := repo.RotateToken(ctx, s.ID, "old-hash", "new-hash", exp, used)
	require.NoError(t, err)
	require.True(t, won)

	mockRepo.On("GetSessionWithUserAndOrgStatus", ctx, s.ID).
		Return((*domain.SessionValidationInfo)(nil), fmt.Errorf("rotated")).Once()
	_, err = repo.GetSessionWithUserAndOrgStatus(ctx, s.ID)
	assert.Error(t, err,
		"post-rotation validation must consult the database, not a cache remnant")

	// Never-cached clause: two consecutive by-id reads must BOTH reach the
	// database — the second returns a value the first could not have cached.
	s2first := &domain.Session{ID: uuid.New(), UserID: uuid.New()}
	s2second := &domain.Session{ID: s2first.ID, UserID: uuid.New()}
	mockRepo.On("GetByID", ctx, s2first.ID).Return(s2first, nil).Once()
	mockRepo.On("GetByID", ctx, s2first.ID).Return(s2second, nil).Once()
	gotS, err := repo.GetByID(ctx, s2first.ID)
	require.NoError(t, err)
	require.Equal(t, s2first.UserID, gotS.UserID)
	gotS, err = repo.GetByID(ctx, s2first.ID)
	require.NoError(t, err)
	assert.Equal(t, s2second.UserID, gotS.UserID,
		"session-by-id read must never be served from a cache: the second read did not consult the database")

	mockRepo.AssertExpectations(t)
}
