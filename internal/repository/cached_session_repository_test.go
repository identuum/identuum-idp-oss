package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func init() {
	logger.InitializeZapLogger()
}

// MockSessionRepository mocks the underlying delegate SessionRepository
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error) {
	args := m.Called(ctx, selector)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) Update(ctx context.Context, session *domain.Session, orgID uuid.UUID) error {
	return m.Called(ctx, session, orgID).Error(0)
}

func (m *MockSessionRepository) RotateToken(context.Context, uuid.UUID, string, string, time.Time, time.Time) (*domain.Session, bool, error) {
	return nil, false, nil
}

func (m *MockSessionRepository) RecordACRUplift(ctx context.Context, sessionID uuid.UUID, upliftAt time.Time, upliftValue string) error {
	return m.Called(ctx, sessionID, upliftAt, upliftValue).Error(0)
}

func (m *MockSessionRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	return m.Called(ctx, id, orgID).Error(0)
}

func (m *MockSessionRepository) Revoke(ctx context.Context, id uuid.UUID, orgID uuid.UUID, reason string) error {
	return m.Called(ctx, id, orgID, reason).Error(0)
}

func (m *MockSessionRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error {
	return m.Called(ctx, userID, reason).Error(0)
}

func (m *MockSessionRepository) RevokeByOrganizationID(ctx context.Context, orgID uuid.UUID, reason string) error {
	return m.Called(ctx, orgID, reason).Error(0)
}

func (m *MockSessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error) {
	args := m.Called(ctx, userID, includeInvalid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *MockSessionRepository) DeleteExpiredReturning(ctx context.Context, retentionPeriod time.Duration, batchSize int) ([]*domain.Session, error) {
	args := m.Called(ctx, retentionPeriod, batchSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetSessionWithUserAndOrgStatus(ctx context.Context, sessionID uuid.UUID) (*domain.SessionValidationInfo, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.SessionValidationInfo), args.Error(1)
}

func (m *MockSessionRepository) GetStats(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockSessionRepository) GetStatsByOrganization(ctx context.Context, orgID uuid.UUID) (map[string]int, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func TestCachedSessionRepository_GetSessionWithUserAndOrgStatus(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()
	info := &domain.SessionValidationInfo{
		Session: &domain.Session{
			ID:     sessionID,
			UserID: userID,
		},
	}

	// miss - call delegate
	mockRepo.On("GetSessionWithUserAndOrgStatus", ctx, sessionID).Return(info, nil).Once()

	res, err := repo.GetSessionWithUserAndOrgStatus(ctx, sessionID)
	assert.NoError(t, err)
	assert.Equal(t, info.Session.ID, res.Session.ID)

	// hit - skip delegate
	res2, err := repo.GetSessionWithUserAndOrgStatus(ctx, sessionID)
	assert.NoError(t, err)
	assert.Equal(t, info.Session.ID, res2.Session.ID)

	mockRepo.AssertExpectations(t)
}

func TestCachedSessionRepository_DeleteExpiredReturning(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()

	s1 := &domain.Session{ID: uuid.New()}
	s2 := &domain.Session{ID: uuid.New()}

	repo.redisClient.Set(ctx, repo.validationKey(s1.ID), &domain.SessionValidationInfo{}, time.Minute)
	repo.redisClient.Set(ctx, repo.validationKey(s2.ID), &domain.SessionValidationInfo{}, time.Minute)

	mockRepo.On("DeleteExpiredReturning", ctx, time.Hour, 10).Return([]*domain.Session{s1, s2}, nil).Once()

	res, err := repo.DeleteExpiredReturning(ctx, time.Hour, 10)
	assert.NoError(t, err)
	assert.Len(t, res, 2)

	mockRepo.AssertExpectations(t)
}

func TestCachedSessionRepository_PassThroughs(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	u1 := uuid.New()
	u2 := uuid.New()

	mockRepo.On("CountActiveByUserID", ctx, u1).Return(5, nil)
	c, e := repo.CountActiveByUserID(ctx, u1)
	assert.NoError(t, e)
	assert.Equal(t, 5, c)

	mockRepo.On("Create", ctx, mock.Anything).Return(&domain.Session{ID: u2}, nil)
	s, e := repo.Create(ctx, &domain.Session{})
	assert.NoError(t, e)
	assert.Equal(t, u2, s.ID)

	mockRepo.On("GetByID", ctx, u1).Return(&domain.Session{ID: u1}, nil)
	s, e = repo.GetByID(ctx, u1)
	assert.NoError(t, e)
	assert.Equal(t, u1, s.ID)
}

// mockAdminSessionRepository embeds MockSessionRepository and additionally
// implements the AdminSessionRepository interface so that the cached session
// repo can enumerate organization sessions for pre-emptive cache invalidation.
type mockAdminSessionRepository struct {
	MockSessionRepository
}

func (m *mockAdminSessionRepository) ListAll(ctx context.Context, filter SessionFilter, pagination Pagination) ([]*domain.Session, int, error) {
	args := m.Called(ctx, filter, pagination)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.Session), args.Int(1), args.Error(2)
}

func (m *mockAdminSessionRepository) ListByOrganizationID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]*domain.Session, int, error) {
	args := m.Called(ctx, orgID, pagination)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.Session), args.Int(1), args.Error(2)
}

func (m *mockAdminSessionRepository) GetStatsByOrganization(ctx context.Context, orgID uuid.UUID) (map[string]int, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

// TestCachedSessionRepository_RevokeByOrganizationID verifies that cached
// session validation entries are invalidated BEFORE the delegate revocation
// is called, preventing a race where a revoked session still validates from cache.
func TestCachedSessionRepository_RevokeByOrganizationID(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(mockAdminSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	orgID := uuid.New()

	s1 := &domain.Session{ID: uuid.New()}
	s2 := &domain.Session{ID: uuid.New()}

	// Seed validation cache entries for s1 and s2
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(s1.ID), &domain.SessionValidationInfo{}, time.Minute))
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(s2.ID), &domain.SessionValidationInfo{}, time.Minute))

	assert.True(t, mr.Exists(repo.validationKey(s1.ID)), "s1 cache key should exist before revocation")
	assert.True(t, mr.Exists(repo.validationKey(s2.ID)), "s2 cache key should exist before revocation")

	// First page contains 2 sessions (< pageSize=500 → final page).
	pg := Pagination{PageSize: 500, Offset: 0}
	mockRepo.On("ListByOrganizationID", ctx, orgID, pg).Return([]*domain.Session{s1, s2}, 2, nil).Once()
	mockRepo.On("RevokeByOrganizationID", ctx, orgID, "org_deleted").Return(nil).Once()

	err = repo.RevokeByOrganizationID(ctx, orgID, "org_deleted")
	require.NoError(t, err)

	// Both cache entries must be absent after revocation (pre-emptive invalidation confirmed)
	assert.False(t, mr.Exists(repo.validationKey(s1.ID)), "s1 cache key must be cleared after revocation")
	assert.False(t, mr.Exists(repo.validationKey(s2.ID)), "s2 cache key must be cleared after revocation")

	mockRepo.AssertExpectations(t)
}

// TestCachedSessionRepository_RevokeByUserID_HappyPath verifies that the
// per-user revoke path evicts every cached validation entry for the user's
// active sessions before the delegate revocation is called. Without this
// assertion, a regression removing the range-Del loop would slip through the
// suite — only the fail-open path is otherwise covered.
func TestCachedSessionRepository_RevokeByUserID_HappyPath(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	userID := uuid.New()

	s1 := &domain.Session{ID: uuid.New(), UserID: userID}
	s2 := &domain.Session{ID: uuid.New(), UserID: userID}

	// Seed validation cache entries for both sessions.
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(s1.ID), &domain.SessionValidationInfo{}, time.Minute))
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(s2.ID), &domain.SessionValidationInfo{}, time.Minute))
	require.True(t, mr.Exists(repo.validationKey(s1.ID)))
	require.True(t, mr.Exists(repo.validationKey(s2.ID)))

	mockRepo.On("ListActiveByUserID", ctx, userID).Return([]*domain.Session{s1, s2}, nil).Once()
	mockRepo.On("RevokeByUserID", ctx, userID, "password_changed").Return(nil).Once()

	require.NoError(t, repo.RevokeByUserID(ctx, userID, "password_changed"))

	// Both cache entries must be cleared after revocation.
	assert.False(t, mr.Exists(repo.validationKey(s1.ID)), "s1 cache key must be cleared after RevokeByUserID")
	assert.False(t, mr.Exists(repo.validationKey(s2.ID)), "s2 cache key must be cleared after RevokeByUserID")

	mockRepo.AssertExpectations(t)
}

// TestCachedSessionRepository_RevokeByUserID_ListError verifies fail-open behaviour:
// if listing active sessions fails, the delegate revocation still proceeds.
func TestCachedSessionRepository_RevokeByUserID_ListError(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	userID := uuid.New()

	// ListActiveByUserID fails (e.g. DB down)
	mockRepo.On("ListActiveByUserID", ctx, userID).Return(([]*domain.Session)(nil), fmt.Errorf("db unavailable")).Once()
	// Delegate revocation must still be attempted (fail-open)
	mockRepo.On("RevokeByUserID", ctx, userID, "password_changed").Return(nil).Once()

	err = repo.RevokeByUserID(ctx, userID, "password_changed")
	require.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

// TestCachedSessionRepository_RevokeByOrganizationID_MultiPage verifies that the
// paginated loop correctly iterates across multiple pages, evicting all cache entries
// when an org has more than pageSize (500) concurrent sessions.
func TestCachedSessionRepository_RevokeByOrganizationID_MultiPage(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(mockAdminSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	orgID := uuid.New()

	// Build 501 sessions: a full first page (500) and a single-session second page.
	page1 := make([]*domain.Session, 500)
	for i := range page1 {
		page1[i] = &domain.Session{ID: uuid.New()}
		require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(page1[i].ID), &domain.SessionValidationInfo{}, time.Minute))
	}
	extra := &domain.Session{ID: uuid.New()}
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(extra.ID), &domain.SessionValidationInfo{}, time.Minute))

	// First call: full page (500 items) → loop continues.
	pg1 := Pagination{PageSize: 500, Offset: 0}
	mockRepo.On("ListByOrganizationID", ctx, orgID, pg1).Return(page1, 500, nil).Once()
	// Second call: partial page (1 item) → loop terminates.
	pg2 := Pagination{PageSize: 500, Offset: 500}
	mockRepo.On("ListByOrganizationID", ctx, orgID, pg2).Return([]*domain.Session{extra}, 1, nil).Once()
	mockRepo.On("RevokeByOrganizationID", ctx, orgID, "org_suspended").Return(nil).Once()

	err = repo.RevokeByOrganizationID(ctx, orgID, "org_suspended")
	require.NoError(t, err)

	// All 501 cache keys must be evicted.
	for _, s := range page1 {
		assert.False(t, mr.Exists(repo.validationKey(s.ID)), "page1 session cache must be cleared")
	}
	assert.False(t, mr.Exists(repo.validationKey(extra.ID)), "extra session cache must be cleared")

	mockRepo.AssertExpectations(t)
}

// TestCachedSessionRepository_RevokeByOrganizationID_ListError_FailOpen verifies
// that a ListByOrganizationID error does not block the underlying database revocation.
func TestCachedSessionRepository_RevokeByOrganizationID_ListError_FailOpen(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(mockAdminSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)

	ctx := context.Background()
	orgID := uuid.New()

	pg := Pagination{PageSize: 500, Offset: 0}
	mockRepo.On("ListByOrganizationID", ctx, orgID, pg).
		Return(([]*domain.Session)(nil), 0, fmt.Errorf("db unavailable")).Once()
	// Even though listing failed, the delegate revocation must be attempted (fail-open).
	mockRepo.On("RevokeByOrganizationID", ctx, orgID, "org_deleted").Return(nil).Once()

	err = repo.RevokeByOrganizationID(ctx, orgID, "org_deleted")
	require.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// Revoking a session — singly, per user, or per organization — evicts its
// cached validation entry, so a revoked session never validates from the
// cache and the next validation consults the database. The seeding goes
// THROUGH the public validation read (miss → delegate → cached; second read
// is a proven hit), so the assertion is about what the serving path returns,
// not merely which keys exist.
// RULE: SESSION-CACHE-REVOKE-1
func TestCachedSessionRepository_RevokedNeverValidatesFromCache(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(mockAdminSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)
	ctx := context.Background()

	// seed caches the session's validation snapshot through the public read
	// path and proves the second read is served from cache (the delegate
	// expectation is .Once — a second delegate call would fail the mock).
	seed := func(s *domain.Session) {
		info := &domain.SessionValidationInfo{Session: s}
		mockRepo.On("GetSessionWithUserAndOrgStatus", ctx, s.ID).Return(info, nil).Once()
		got, seedErr := repo.GetSessionWithUserAndOrgStatus(ctx, s.ID)
		require.NoError(t, seedErr)
		require.Equal(t, s.ID, got.Session.ID)
		got, seedErr = repo.GetSessionWithUserAndOrgStatus(ctx, s.ID)
		require.NoError(t, seedErr)
		require.Equal(t, s.ID, got.Session.ID)
		require.True(t, mr.Exists(repo.validationKey(s.ID)))
	}

	// 1) Single-session Revoke.
	s1 := &domain.Session{ID: uuid.New()}
	seed(s1)
	mockRepo.On("Revoke", ctx, s1.ID, uuid.Nil, "test_revoke").Return(nil).Once()
	require.NoError(t, repo.Revoke(ctx, s1.ID, uuid.Nil, "test_revoke"))
	assert.False(t, mr.Exists(repo.validationKey(s1.ID)),
		"revoked session must not validate from cache: Revoke left the cached validation entry behind")
	// The NEXT validation must consult the database, not a cache remnant.
	mockRepo.On("GetSessionWithUserAndOrgStatus", ctx, s1.ID).
		Return((*domain.SessionValidationInfo)(nil), fmt.Errorf("session revoked")).Once()
	_, err = repo.GetSessionWithUserAndOrgStatus(ctx, s1.ID)
	assert.Error(t, err, "post-revoke validation must consult the database, not a cache remnant")

	// 2) RevokeByUserID evicts every active session's entry.
	userID := uuid.New()
	s2 := &domain.Session{ID: uuid.New(), UserID: userID}
	s3 := &domain.Session{ID: uuid.New(), UserID: userID}
	seed(s2)
	seed(s3)
	mockRepo.On("ListActiveByUserID", ctx, userID).Return([]*domain.Session{s2, s3}, nil).Once()
	mockRepo.On("RevokeByUserID", ctx, userID, "password_changed").Return(nil).Once()
	require.NoError(t, repo.RevokeByUserID(ctx, userID, "password_changed"))
	assert.False(t, mr.Exists(repo.validationKey(s2.ID)),
		"user-revoked session must not validate from cache (s2 entry survived RevokeByUserID)")
	assert.False(t, mr.Exists(repo.validationKey(s3.ID)),
		"user-revoked session must not validate from cache (s3 entry survived RevokeByUserID)")

	// 3) RevokeByOrganizationID evicts every org session's entry.
	orgID := uuid.New()
	s4 := &domain.Session{ID: uuid.New()}
	seed(s4)
	pg := Pagination{PageSize: 500, Offset: 0}
	mockRepo.On("ListByOrganizationID", ctx, orgID, pg).Return([]*domain.Session{s4}, 1, nil).Once()
	mockRepo.On("RevokeByOrganizationID", ctx, orgID, "org_deleted").Return(nil).Once()
	require.NoError(t, repo.RevokeByOrganizationID(ctx, orgID, "org_deleted"))
	assert.False(t, mr.Exists(repo.validationKey(s4.ID)),
		"org-revoked session must not validate from cache (entry survived RevokeByOrganizationID)")

	mockRepo.AssertExpectations(t)
}
