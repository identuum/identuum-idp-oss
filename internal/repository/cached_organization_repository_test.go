package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestCachedOrganizationRepository_GetByID(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	expectedOrg := &domain.Organization{
		ID:      orgID,
		Domain:  "example.com",
		OrgSlug: "example-org",
	}

	// 1. Cache Miss
	mockRepo.On("GetByID", ctx, orgID).Return(expectedOrg, nil).Once()

	org, err := cachedRepo.GetByID(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, org.ID)
	mockRepo.AssertExpectations(t)

	// 2. Cache Hit
	// mockRepo is not configured for a second call - if it delegates, test fails
	org2, err := cachedRepo.GetByID(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, org2.ID)
}

func TestCachedOrganizationRepository_GetByDomain(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	domainName := "tech.example.com"

	expectedOrg := &domain.Organization{
		ID:      orgID,
		Domain:  domainName,
		OrgSlug: "tech-example",
	}

	// 1. Cache Miss
	mockRepo.On("GetByDomain", ctx, domainName).Return(expectedOrg, nil).Once()

	org, err := cachedRepo.GetByDomain(ctx, domainName)
	assert.NoError(t, err)
	assert.Equal(t, domainName, org.Domain)
	mockRepo.AssertExpectations(t)

	// 2. Cache Hit
	org2, err := cachedRepo.GetByDomain(ctx, domainName)
	assert.NoError(t, err)
	assert.Equal(t, domainName, org2.Domain)
}

func TestCachedOrganizationRepository_GetBySlug(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	slug := "test-slug"

	expectedOrg := &domain.Organization{
		ID:      orgID,
		Domain:  "slug.example.com",
		OrgSlug: slug,
	}

	mockRepo.On("GetBySlug", ctx, slug).Return(expectedOrg, nil).Once()

	org, err := cachedRepo.GetBySlug(ctx, slug)
	assert.NoError(t, err)
	assert.Equal(t, slug, org.OrgSlug)
	mockRepo.AssertExpectations(t)

	// Hit
	org2, err := cachedRepo.GetBySlug(ctx, slug)
	assert.NoError(t, err)
	assert.Equal(t, slug, org2.OrgSlug)
}

func TestCachedOrganizationRepository_Invalidation_On_Update(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 10*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	oldOrg := &domain.Organization{
		ID:      orgID,
		Domain:  "old.example.com",
		OrgSlug: "old-slug",
	}

	// Seed caches
	mockRepo.On("GetByID", ctx, orgID).Return(oldOrg, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, orgID)
	mockRepo.On("GetByDomain", ctx, "old.example.com").Return(oldOrg, nil).Once()
	_, _ = cachedRepo.GetByDomain(ctx, "old.example.com")
	mockRepo.On("GetBySlug", ctx, "old-slug").Return(oldOrg, nil).Once()
	_, _ = cachedRepo.GetBySlug(ctx, "old-slug")

	assert.True(t, mr.Exists(cachedRepo.idKey(orgID)))
	assert.True(t, mr.Exists(cachedRepo.domainKey("old.example.com")))
	assert.True(t, mr.Exists("org:slug:old-slug"))

	newOrgName := "New Org"
	opts := UpdateOrganizationOptions{Name: &newOrgName}
	updatedOrg := &domain.Organization{
		ID:      orgID,
		Domain:  "new.example.com",
		OrgSlug: "new-slug",
		Name:    newOrgName,
	}

	// Update sequence: GetByID (internal invalidate), Update
	mockRepo.On("GetByID", ctx, orgID).Return(oldOrg, nil).Once()
	mockRepo.On("Update", ctx, orgID, opts).Return(updatedOrg, nil).Once()

	_, err := cachedRepo.Update(ctx, orgID, opts)
	assert.NoError(t, err)

	// Verify all old keys and new keys are invalidated
	assert.False(t, mr.Exists(cachedRepo.idKey(orgID)))
	assert.False(t, mr.Exists(cachedRepo.domainKey("old.example.com")))
	assert.False(t, mr.Exists("org:slug:old-slug"))

	mockRepo.AssertExpectations(t)
}

func TestCachedOrganizationRepository_Delete(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 10*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	org := &domain.Organization{
		ID:      orgID,
		Domain:  "del.example.com",
		OrgSlug: "del-slug",
	}

	// Seed ID cache
	mockRepo.On("GetByID", ctx, orgID).Return(org, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, orgID)
	assert.True(t, mr.Exists(cachedRepo.idKey(orgID)))

	mockRepo.On("GetByID", ctx, orgID).Return(org, nil).Once()
	mockRepo.On("Delete", ctx, orgID).Return(nil).Once()

	err := cachedRepo.Delete(ctx, orgID)
	assert.NoError(t, err)

	assert.False(t, mr.Exists(cachedRepo.idKey(orgID)))
	mockRepo.AssertExpectations(t)
}

func TestCachedOrganizationRepository_UpdateID(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 10*time.Minute)

	ctx := context.Background()
	oldID := uuid.New()
	newID := uuid.New()

	org := &domain.Organization{
		ID:      oldID,
		Domain:  "swap.example.com",
		OrgSlug: "swap-slug",
	}

	// Mock sequence
	mockRepo.On("GetByID", ctx, oldID).Return(org, nil).Once() // Seed + Invalidate pre-fetch is cached
	_, _ = cachedRepo.GetByID(ctx, oldID)

	// Ensure populated
	assert.True(t, mr.Exists(cachedRepo.idKey(oldID)))

	mockRepo.On("UpdateID", ctx, oldID, newID).Return(nil).Once()

	err := cachedRepo.UpdateID(ctx, oldID, newID)
	assert.NoError(t, err)

	// Verify caches are flushed
	assert.False(t, mr.Exists(cachedRepo.idKey(oldID)))
	assert.False(t, mr.Exists(cachedRepo.idKey(newID))) // New shouldn't exist
	mockRepo.AssertExpectations(t)
}

func TestCachedOrganizationRepository_Passthrough(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID}

	// Create
	mockRepo.On("Create", ctx, org).Return(org, nil).Once()
	res, err := cachedRepo.Create(ctx, org)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res.ID)

	// CreateWithAdmin
	user := &domain.User{ID: uuid.New()}
	mockRepo.On("CreateWithAdmin", ctx, org, user).Return(org, user, nil).Once()
	res, u2, err := cachedRepo.CreateWithAdmin(ctx, org, user)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res.ID)
	assert.Equal(t, user.ID, u2.ID)

	// Undelete
	mockRepo.On("Undelete", ctx, orgID).Return(nil).Once()
	mockRepo.On("GetByID", ctx, orgID).Return(org, nil).Once() // for cache invalidate
	err = cachedRepo.Undelete(ctx, orgID)
	assert.NoError(t, err)

	// List
	mockRepo.On("List", ctx, OrganizationFilter{}, Pagination{}, Sort{}).Return([]*domain.Organization{org}, 1, nil).Once()
	lRes, c, err := cachedRepo.List(ctx, OrganizationFilter{}, Pagination{}, Sort{})
	assert.NoError(t, err)
	assert.Len(t, lRes, 1)
	assert.Equal(t, 1, c)

	// CountUsers
	mockRepo.On("CountUsers", ctx, orgID).Return(5, nil).Once()
	count, err := cachedRepo.CountUsers(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, 5, count)

	// CountSessions
	mockRepo.On("CountSessions", ctx, orgID).Return(10, nil).Once()
	c2, err := cachedRepo.CountSessions(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, 10, c2)
}

func TestCachedOrganizationRepository_AdminPassthrough(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID}
	stats := map[string]int{"users": 5}

	mockRepo.On("GetDetailsAdmin", ctx, orgID).Return(org, stats, nil).Once()
	res, rStats, err := cachedRepo.GetDetailsAdmin(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res.ID)
	assert.Equal(t, 5, rStats["users"])

	mockRepo.On("GetByIDAdmin", ctx, orgID).Return(org, nil).Once()
	res, err = cachedRepo.GetByIDAdmin(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res.ID)

	mockRepo.On("ListDeleted", ctx, Pagination{}).Return([]*domain.Organization{org}, 1, nil).Once()
	lRes, count, err := cachedRepo.ListDeleted(ctx, Pagination{})
	assert.NoError(t, err)
	assert.Len(t, lRes, 1)
	assert.Equal(t, 1, count)

	mockRepo.On("ListAll", ctx, OrganizationFilter{}, Pagination{}, Sort{}).Return([]*domain.Organization{org}, 1, nil).Once()
	lRes, count, err = cachedRepo.ListAll(ctx, OrganizationFilter{}, Pagination{}, Sort{})
	assert.NoError(t, err)
	assert.Len(t, lRes, 1)
	assert.Equal(t, 1, count)

	// HardDelete (invalidates cache)
	mockRepo.On("GetByID", ctx, orgID).Return(org, nil).Once()
	mockRepo.On("HardDelete", ctx, orgID).Return(nil).Once()
	err = cachedRepo.HardDelete(ctx, orgID)
	assert.NoError(t, err)
}

// TestCachedOrganizationRepository_GetDetails pins the F1 fix: the org portion
// must hit the GetByID cache on subsequent calls (no duplicate GetByID
// delegate call), but the child-table counts MUST be fetched fresh on every
// call so a sibling-repo mutation (new user, revoked session) is reflected
// without waiting for TTL.
func TestCachedOrganizationRepository_GetDetails(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()
	expectedOrg := &domain.Organization{ID: orgID, Domain: "test.com"}

	// Org is fetched once via GetByID; subsequent GetDetails calls serve it
	// from cache. CountUsers / CountSessions are fetched fresh on every call.
	mockRepo.On("GetByID", ctx, orgID).Return(expectedOrg, nil).Once()
	mockRepo.On("CountUsers", ctx, orgID).Return(10, nil).Twice()
	mockRepo.On("CountSessions", ctx, orgID).Return(7, nil).Once()
	mockRepo.On("CountSessions", ctx, orgID).Return(8, nil).Once()

	org1, stats1, err := cachedRepo.GetDetails(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, org1.ID)
	assert.Equal(t, 10, stats1["user_count"])
	assert.Equal(t, 7, stats1["session_count"])

	// Second call: org served from cache (no second GetByID), counts refreshed
	// so a change in session_count propagates immediately.
	org2, stats2, err := cachedRepo.GetDetails(ctx, orgID)
	assert.NoError(t, err)
	assert.Equal(t, orgID, org2.ID)
	assert.Equal(t, 10, stats2["user_count"])
	assert.Equal(t, 8, stats2["session_count"], "session_count must be fetched fresh on each GetDetails call")

	mockRepo.AssertExpectations(t)
}

func TestCachedOrganizationRepository_SilentInvalidationFallback(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(MockOrganizationRepository)
	cachedRepo := NewCachedOrganizationRepository(mockRepo, rdb, 10*time.Minute)

	ctx := context.Background()
	orgID := uuid.New()

	org := &domain.Organization{
		ID:      orgID,
		Domain:  "del.example.com",
		OrgSlug: "del-slug",
	}

	// Seed ID cache
	mockRepo.On("GetByID", ctx, orgID).Return(org, nil).Once()
	_, _ = cachedRepo.GetByID(ctx, orgID)
	assert.True(t, mr.Exists(cachedRepo.idKey(orgID)))

	// Mock GetByID failure (e.g. schema error) during the fetch for invalidation
	mockRepo.On("GetByID", ctx, orgID).Return((*domain.Organization)(nil), errors.New("simulated db err")).Once()

	// Ensure delete proceeds
	mockRepo.On("Delete", ctx, orgID).Return(nil).Once()

	err := cachedRepo.Delete(ctx, orgID)
	assert.NoError(t, err)

	// Since GetByID failed, org is nil, but fallback should remove idKey
	assert.False(t, mr.Exists(cachedRepo.idKey(orgID)))
	mockRepo.AssertExpectations(t)
}
