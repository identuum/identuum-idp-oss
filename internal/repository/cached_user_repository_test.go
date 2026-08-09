package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAdminUserRepository struct {
	MockUserRepository
}

func (m *mockAdminUserRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	var x *domain.User
	if a := args.Get(0); a != nil {
		x = a.(*domain.User)
	}
	return x, args.Error(1)
}

func (m *mockAdminUserRepository) GetByEmailAdmin(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	var x *domain.User
	if a := args.Get(0); a != nil {
		x = a.(*domain.User)
	}
	return x, args.Error(1)
}

func (m *mockAdminUserRepository) ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.User, int, error) {
	args := m.Called(ctx, pagination)
	var x []*domain.User
	if a := args.Get(0); a != nil {
		x = a.([]*domain.User)
	}
	return x, args.Int(1), args.Error(2)
}

func (m *mockAdminUserRepository) ListAll(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error) {
	args := m.Called(ctx, opts)
	var x []*domain.User
	if a := args.Get(0); a != nil {
		x = a.([]*domain.User)
	}
	return x, args.Int(1), args.Error(2)
}

func (m *mockAdminUserRepository) HardDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *cache.RedisClient) {
	mr := miniredis.RunT(t)
	client, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)
	return mr, client
}

func TestCachedUserRepository_GetByID(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	orgID := uuid.New()

	expectedUser := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "test@example.com",
	}

	// 1. Cache Miss: Should call delegate and then cache it
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()

	user, err := cachedRepo.GetByID(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.ID, user.ID)
	mockRepo.AssertExpectations(t)

	// 2. Cache Hit: Should NOT call delegate
	// mockRepo.On is not set up intentionally; if it calls delegate, it'll fail
	user2, err := cachedRepo.GetByID(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.ID, user2.ID)
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_CountByOrganization(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	// 1. Cache Miss
	mockRepo.On("CountByOrganization", ctx, orgID).Return(42, nil).Once()

	count, err := cachedRepo.CountByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, 42, count)
	mockRepo.AssertExpectations(t)

	// 2. Cache Hit
	count2, err := cachedRepo.CountByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, 42, count2)
}

func TestCachedUserRepository_Invalidation_On_Update(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	orgID := uuid.New()

	expectedUser := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "old@example.com",
	}

	// Seed cache
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, userID)

	// Ensure it's in cache
	key := cachedRepo.idKey(userID)
	assert.True(t, mr.Exists(key))

	newName := "New Name"
	opts := UpdateUserOptions{Name: &newName}
	updatedUser := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "new@example.com",
		Name:           &newName,
	}

	// Mock GetByID for old user cache invalidation, and delegate Update
	// Note: Update internally fetches GetByID first to find the old email
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	mockRepo.On("Update", ctx, userID, orgID, opts).Return(updatedUser, nil).Once()

	result, err := cachedRepo.Update(ctx, userID, orgID, opts)
	assert.NoError(t, err)
	assert.Equal(t, newName, *result.Name)

	// Old cache should be gone, but wait... Update calls invalidateUserCache for old user AND new user.
	// But `invalidateUserCache` just issues Redis DEL.
	// This means the cache should be empty for GetByID immediately after an update.
	assert.False(t, mr.Exists(key))
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_Create(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	user := &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "create@example.com",
	}

	mockRepo.On("Create", ctx, user).Return(user, nil).Once()

	created, err := cachedRepo.Create(ctx, user)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, created.ID)
	mockRepo.AssertExpectations(t)

	// Create does not cache, but it's passed through
}

func TestCachedUserRepository_FindUsersByEmail(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	email := "test@example.com"
	users := []*domain.User{{ID: uuid.New(), Email: email}}

	mockRepo.On("FindUsersByEmail", ctx, email).Return(users, nil).Once()

	res, err := cachedRepo.FindUsersByEmail(ctx, email)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_GetByEmailAndOrgID(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	email := "test@example.com"
	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), Email: email, OrganizationID: orgID}

	// Cache miss
	mockRepo.On("GetByEmailAndOrgID", ctx, orgID, email).Return(user, nil).Once()

	res, err := cachedRepo.GetByEmailAndOrgID(ctx, orgID, email)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res.ID)
	mockRepo.AssertExpectations(t)

	// Cache hit
	res2, err := cachedRepo.GetByEmailAndOrgID(ctx, orgID, email)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res2.ID)
}

func TestCachedUserRepository_GetByExternalID(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	extID := "ext-123"
	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), ExternalID: &extID, OrganizationID: orgID}

	// Cache miss
	mockRepo.On("GetByExternalID", ctx, orgID, extID).Return(user, nil).Once()

	res, err := cachedRepo.GetByExternalID(ctx, orgID, extID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res.ID)
	mockRepo.AssertExpectations(t)

	// Cache hit
	res2, err := cachedRepo.GetByExternalID(ctx, orgID, extID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res2.ID)
}

func TestCachedUserRepository_GetByIDWithOrg(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	user := &domain.User{ID: userID}

	// Cache miss
	mockRepo.On("GetByIDWithOrg", ctx, userID).Return(user, nil).Once()

	res, err := cachedRepo.GetByIDWithOrg(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res.ID)
	mockRepo.AssertExpectations(t)

	// Cache hit
	res2, err := cachedRepo.GetByIDWithOrg(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, res2.ID)
}

func TestCachedUserRepository_CountOrgAdminsByOrganization(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	mockRepo.On("CountOrgAdminsByOrganization", ctx, orgID).Return(2, nil).Once()

	res, err := cachedRepo.CountOrgAdminsByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, 2, res)
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_CountOrgAdminsByOrganizations(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgIDs := []uuid.UUID{uuid.New()}
	expected := map[uuid.UUID]int{orgIDs[0]: 3}

	mockRepo.On("CountOrgAdminsByOrganizations", ctx, orgIDs).Return(expected, nil).Once()

	res, err := cachedRepo.CountOrgAdminsByOrganizations(ctx, orgIDs)
	assert.NoError(t, err)
	assert.Equal(t, expected, res)
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_PassThroughs(t *testing.T) {
	// Tests for generic pass-through methods like Undelete, UpdateLastLogin, VerifyPassword, etc
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	orgID := uuid.New()

	// Undelete -> invalidates cache
	mockRepo.On("Undelete", ctx, userID, orgID).Return(nil).Once()
	err := cachedRepo.Undelete(ctx, userID, orgID)
	assert.NoError(t, err)

	// UpdateLastLogin
	mockRepo.On("UpdateLastLogin", ctx, userID).Return(nil).Once()
	err = cachedRepo.UpdateLastLogin(ctx, userID)
	assert.NoError(t, err)

	// VerifyPassword
	mockRepo.On("VerifyPassword", ctx, "pass", "hash").Return(nil).Once()
	err = cachedRepo.VerifyPassword(ctx, "pass", "hash")
	assert.NoError(t, err)

	// HashPassword
	mockRepo.On("HashPassword", "pass").Return("hash", nil).Once()
	hash, err := cachedRepo.HashPassword("pass")
	assert.NoError(t, err)
	assert.Equal(t, "hash", hash)

	// GetUserOrganization
	org := &domain.Organization{ID: orgID}
	mockRepo.On("GetUserOrganization", ctx, userID).Return(org, nil).Once()
	resOrg, err := cachedRepo.GetUserOrganization(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, org.ID, resOrg.ID)

	// UpdateOrganizationID
	// Expect GetByID to fetch the user before cache invalidation
	mockRepo.On("GetByID", ctx, userID).Return(&domain.User{ID: userID, OrganizationID: uuid.New()}, nil).Once()
	mockRepo.On("UpdateOrganizationID", ctx, userID, orgID).Return(nil).Once()
	err = cachedRepo.UpdateOrganizationID(ctx, userID, orgID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_AdminPassThroughs(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockAdminUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()

	// GetByIDAdmin
	userObj := &domain.User{ID: userID}
	mockRepo.On("GetByIDAdmin", ctx, userID).Return(userObj, nil).Once()
	resUser, err := cachedRepo.GetByIDAdmin(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, userID, resUser.ID)

	// GetByEmailAdmin
	mockRepo.On("GetByEmailAdmin", ctx, "admin@test.com").Return(userObj, nil).Once()
	resUser2, err := cachedRepo.GetByEmailAdmin(ctx, "admin@test.com")
	assert.NoError(t, err)
	assert.Equal(t, userID, resUser2.ID)

	// HardDelete
	mockRepo.On("HardDelete", ctx, userID).Return(nil).Once()
	err = cachedRepo.HardDelete(ctx, userID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_ListPassThroughs(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockAdminUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	opts := ListUserOptions{
		Filter:     UserFilter{},
		Pagination: Pagination{},
		Sort:       Sort{},
	}
	expectedList := []*domain.User{{ID: uuid.New()}}

	mockRepo.On("List", ctx, opts).Return(expectedList, 1, nil).Once()
	list1, c1, err := cachedRepo.List(ctx, opts)
	assert.NoError(t, err)
	assert.Len(t, list1, 1)
	assert.Equal(t, 1, c1)

	mockRepo.On("ListByOrganization", ctx, orgID, opts).Return(expectedList, 1, nil).Once()
	list2, c2, err := cachedRepo.ListByOrganization(ctx, orgID, opts)
	assert.NoError(t, err)
	assert.Len(t, list2, 1)
	assert.Equal(t, 1, c2)

	mockRepo.On("ListAll", ctx, opts).Return(expectedList, 1, nil).Once()
	list3, c3, err := cachedRepo.ListAll(ctx, opts)
	assert.NoError(t, err)
	assert.Len(t, list3, 1)
	assert.Equal(t, 1, c3)

	mockRepo.On("ListDeleted", ctx, opts.Pagination).Return(expectedList, 1, nil).Once()
	list4, c4, err := cachedRepo.ListDeleted(ctx, opts.Pagination)
	assert.NoError(t, err)
	assert.Len(t, list4, 1)
	assert.Equal(t, 1, c4)

	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_Delete(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	orgID := uuid.New()

	expectedUser := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "test@example.com",
	}

	// Seed
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, userID)
	assert.True(t, mr.Exists(cachedRepo.idKey(userID)))

	// Delete
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	mockRepo.On("Delete", ctx, userID, orgID).Return(nil).Once()

	err := cachedRepo.Delete(ctx, userID, orgID)
	assert.NoError(t, err)

	// Cache should be blown away
	assert.False(t, mr.Exists(cachedRepo.idKey(userID)))
	mockRepo.AssertExpectations(t)
}

func TestCachedUserRepository_SilentInvalidationFallback(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockUserRepository)
	cachedRepo := NewCachedUserRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	userID := uuid.New()
	orgID := uuid.New()

	expectedUser := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "test@example.com",
	}

	// Seed cache
	mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, userID)
	assert.True(t, mr.Exists(cachedRepo.idKey(userID)))

	// Delete with fallback
	mockRepo.On("GetByID", ctx, userID).Return((*domain.User)(nil), errors.New("simulated db err")).Once()
	mockRepo.On("Delete", ctx, userID, orgID).Return(nil).Once()

	err := cachedRepo.Delete(ctx, userID, orgID)
	assert.NoError(t, err)

	// Cache should be blown away even if GetByID failed
	assert.False(t, mr.Exists(cachedRepo.idKey(userID)))
	mockRepo.AssertExpectations(t)
}
