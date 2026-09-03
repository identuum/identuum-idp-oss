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

type mockServiceAccountRepository struct {
	mock.Mock
}

func (m *mockServiceAccountRepository) Create(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, sa)
	var x *domain.ServiceAccount
	if a := args.Get(0); a != nil {
		x = a.(*domain.ServiceAccount)
	}
	return x, args.Error(1)
}

func (m *mockServiceAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, id)
	var x *domain.ServiceAccount
	if a := args.Get(0); a != nil {
		x = a.(*domain.ServiceAccount)
	}
	return x, args.Error(1)
}

func (m *mockServiceAccountRepository) GetByName(ctx context.Context, orgID uuid.UUID, name string) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, orgID, name)
	var x *domain.ServiceAccount
	if a := args.Get(0); a != nil {
		x = a.(*domain.ServiceAccount)
	}
	return x, args.Error(1)
}

func (m *mockServiceAccountRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	args := m.Called(ctx, orgID)
	var x []*domain.ServiceAccount
	if a := args.Get(0); a != nil {
		x = a.([]*domain.ServiceAccount)
	}
	return x, args.Error(1)
}

func (m *mockServiceAccountRepository) Update(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, sa)
	var x *domain.ServiceAccount
	if a := args.Get(0); a != nil {
		x = a.(*domain.ServiceAccount)
	}
	return x, args.Error(1)
}

func (m *mockServiceAccountRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

func (m *mockServiceAccountRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func TestCachedServiceAccountRepository_Getters(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockServiceAccountRepository)
	cachedRepo := NewCachedServiceAccountRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	id := uuid.New()
	orgID := uuid.New()
	name := "test-sa"
	expectedSA := &domain.ServiceAccount{ID: id, OrganizationID: orgID, Name: name}

	// GetByID
	mockRepo.On("GetByID", ctx, id).Return(expectedSA, nil).Once()
	res, err := cachedRepo.GetByID(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, id, res.ID)

	// Hit
	res2, err := cachedRepo.GetByID(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, id, res2.ID)

	mockRepo.AssertExpectations(t)
}

func TestCachedServiceAccountRepository_Mutations(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockServiceAccountRepository)
	cachedRepo := NewCachedServiceAccountRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	id := uuid.New()
	orgID := uuid.New()
	sa := &domain.ServiceAccount{ID: id, OrganizationID: orgID, Name: "test"}

	// Create pass-through
	mockRepo.On("Create", ctx, sa).Return(sa, nil).Once()
	res, err := cachedRepo.Create(ctx, sa)
	assert.NoError(t, err)
	assert.Equal(t, id, res.ID)

	// List pass-through
	mockRepo.On("ListByOrganization", ctx, orgID).Return([]*domain.ServiceAccount{sa}, nil).Once()
	list, err := cachedRepo.ListByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	// GetByName pass-through
	mockRepo.On("GetByName", ctx, orgID, "test").Return(sa, nil).Once()
	res3, err := cachedRepo.GetByName(ctx, orgID, "test")
	assert.NoError(t, err)
	assert.Equal(t, orgID, res3.OrganizationID)

	// Update
	mockRepo.On("Update", ctx, sa).Return(sa, nil).Once()
	res2, err := cachedRepo.Update(ctx, sa)
	assert.NoError(t, err)
	assert.Equal(t, id, res2.ID)

	// Delete
	mockRepo.On("GetByID", ctx, id).Return(sa, nil).Once()
	mockRepo.On("Delete", ctx, id, orgID).Return(nil).Once()
	err = cachedRepo.Delete(ctx, id, orgID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// UpdateActive (slice identuum-20260530-service-account-disable-enable-backend).
func (m *mockServiceAccountRepository) UpdateActive(ctx context.Context, id uuid.UUID, orgID uuid.UUID, active bool) error {
	args := m.Called(ctx, id, orgID, active)
	return args.Error(0)
}

// UpdateOwner (THE-OWNERLESS-ACCOUNT).
func (m *mockServiceAccountRepository) UpdateOwner(ctx context.Context, id uuid.UUID, orgID uuid.UUID, ownerUserID uuid.UUID) error {
	args := m.Called(ctx, id, orgID, ownerUserID)
	return args.Error(0)
}
