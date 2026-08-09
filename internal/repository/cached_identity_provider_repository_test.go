package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func init() {
	logger.InitializeZapLogger()
}

type mockIdentityProviderRepository struct {
	mock.Mock
}

func (m *mockIdentityProviderRepository) Create(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, provider)
	var x *domain.IdentityProvider
	if a := args.Get(0); a != nil {
		x = a.(*domain.IdentityProvider)
	}
	return x, args.Error(1)
}

func (m *mockIdentityProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, id)
	var x *domain.IdentityProvider
	if a := args.Get(0); a != nil {
		x = a.(*domain.IdentityProvider)
	}
	return x, args.Error(1)
}

func (m *mockIdentityProviderRepository) GetByOrgAndType(ctx context.Context, orgID uuid.UUID, providerType domain.IdentityProviderType) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, orgID, providerType)
	var x *domain.IdentityProvider
	if a := args.Get(0); a != nil {
		x = a.(*domain.IdentityProvider)
	}
	return x, args.Error(1)
}

func (m *mockIdentityProviderRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	args := m.Called(ctx, orgID)
	var x []*domain.IdentityProvider
	if a := args.Get(0); a != nil {
		x = a.([]*domain.IdentityProvider)
	}
	return x, args.Error(1)
}

func (m *mockIdentityProviderRepository) Update(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, provider)
	var x *domain.IdentityProvider
	if a := args.Get(0); a != nil {
		x = a.(*domain.IdentityProvider)
	}
	return x, args.Error(1)
}

func (m *mockIdentityProviderRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

func TestCachedIdentityProviderRepository_Getters(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockIdentityProviderRepository)
	cachedRepo := NewCachedIdentityProviderRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	id := uuid.New()
	orgID := uuid.New()
	pType := domain.IdentityProviderType("ldap")
	expectedProv := &domain.IdentityProvider{ID: id, OrganizationID: orgID, Type: pType}

	// GetByID
	mockRepo.On("GetByID", ctx, id).Return(expectedProv, nil).Once()
	res, err := cachedRepo.GetByID(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, id, res.ID)

	// Hit
	res2, err := cachedRepo.GetByID(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, id, res2.ID)

	// GetByOrgAndType
	mockRepo.On("GetByOrgAndType", ctx, orgID, pType).Return(expectedProv, nil).Once()
	res3, err := cachedRepo.GetByOrgAndType(ctx, orgID, pType)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res3.OrganizationID)

	// Hit
	res4, err := cachedRepo.GetByOrgAndType(ctx, orgID, pType)
	assert.NoError(t, err)
	assert.Equal(t, orgID, res4.OrganizationID)

	// ListByOrganization
	mockRepo.On("ListByOrganization", ctx, orgID).Return([]*domain.IdentityProvider{expectedProv}, nil).Once()
	list, err := cachedRepo.ListByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	// Hit
	list2, err := cachedRepo.ListByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Len(t, list2, 1)

	mockRepo.AssertExpectations(t)
}

func TestCachedIdentityProviderRepository_Mutations(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockIdentityProviderRepository)
	cachedRepo := NewCachedIdentityProviderRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	id := uuid.New()
	orgID := uuid.New()
	prov := &domain.IdentityProvider{ID: id, OrganizationID: orgID, Type: "ldap"}

	// Create
	mockRepo.On("Create", ctx, prov).Return(prov, nil).Once()
	res, err := cachedRepo.Create(ctx, prov)
	assert.NoError(t, err)
	assert.Equal(t, id, res.ID)

	// Update
	mockRepo.On("GetByID", ctx, id).Return(prov, nil).Once()
	mockRepo.On("Update", ctx, prov).Return(prov, nil).Once()
	res2, err := cachedRepo.Update(ctx, prov)
	assert.NoError(t, err)
	assert.Equal(t, id, res2.ID)

	// Delete
	mockRepo.On("GetByID", ctx, id).Return(prov, nil).Once()
	mockRepo.On("Delete", ctx, id, orgID).Return(nil).Once()
	err = cachedRepo.Delete(ctx, id, orgID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
