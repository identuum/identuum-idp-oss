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

type mockClientRepository struct {
	mock.Mock
}

func (m *mockClientRepository) RegisterClient(ctx context.Context, client *domain.Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockClientRepository) GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	args := m.Called(ctx, id)
	var x *domain.Client
	if a := args.Get(0); a != nil {
		x = a.(*domain.Client)
	}
	return x, args.Error(1)
}

func (m *mockClientRepository) GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	args := m.Called(ctx, clientID)
	var x *domain.Client
	if a := args.Get(0); a != nil {
		x = a.(*domain.Client)
	}
	return x, args.Error(1)
}

func (m *mockClientRepository) Update(ctx context.Context, client *domain.Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockClientRepository) Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

func (m *mockClientRepository) List(ctx context.Context, pagination Pagination, orgID *uuid.UUID) ([]*domain.Client, int, error) {
	args := m.Called(ctx, pagination, orgID)
	var x []*domain.Client
	if a := args.Get(0); a != nil {
		x = a.([]*domain.Client)
	}
	return x, args.Int(1), args.Error(2)
}

func (m *mockClientRepository) ListByServiceAccountID(ctx context.Context, orgID uuid.UUID, saID uuid.UUID) ([]*domain.Client, error) {
	args := m.Called(ctx, orgID, saID)
	var x []*domain.Client
	if a := args.Get(0); a != nil {
		x = a.([]*domain.Client)
	}
	return x, args.Error(1)
}

func (m *mockClientRepository) SaveConsent(ctx context.Context, consent *domain.Consent) error {
	args := m.Called(ctx, consent)
	return args.Error(0)
}

func (m *mockClientRepository) GetConsent(ctx context.Context, userID, clientID uuid.UUID, apiResourceID *uuid.UUID) (*domain.Consent, error) {
	args := m.Called(ctx, userID, clientID, apiResourceID)
	var x *domain.Consent
	if a := args.Get(0); a != nil {
		x = a.(*domain.Consent)
	}
	return x, args.Error(1)
}

func TestCachedClientRepository_Getters(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockClientRepository)
	cachedRepo := NewCachedClientRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	clientID := uuid.New()
	pubClientID := "public-id"
	expectedClient := &domain.Client{
		ID:       clientID,
		ClientID: pubClientID,
	}

	// GetClientByID
	mockRepo.On("GetClientByID", ctx, clientID).Return(expectedClient, nil).Once()
	res, err := cachedRepo.GetClientByID(ctx, clientID)
	assert.NoError(t, err)
	assert.Equal(t, clientID, res.ID)

	// Hit GetClientByID
	res2, err := cachedRepo.GetClientByID(ctx, clientID)
	assert.NoError(t, err)
	assert.Equal(t, clientID, res2.ID)

	// GetClientByClientID
	mockRepo.On("GetClientByClientID", ctx, pubClientID).Return(expectedClient, nil).Once()
	res3, err := cachedRepo.GetClientByClientID(ctx, pubClientID)
	assert.NoError(t, err)
	assert.Equal(t, pubClientID, res3.ClientID)

	// Hit GetClientByClientID
	res4, err := cachedRepo.GetClientByClientID(ctx, pubClientID)
	assert.NoError(t, err)
	assert.Equal(t, pubClientID, res4.ClientID)

	// GetConsent
	userID := uuid.New()
	apiResID := uuid.New()
	expectedConsent := &domain.Consent{
		UserID:        userID,
		ClientID:      clientID,
		APIResourceID: &apiResID,
	}

	mockRepo.On("GetConsent", ctx, userID, clientID, &apiResID).Return(expectedConsent, nil).Once()
	con, err := cachedRepo.GetConsent(ctx, userID, clientID, &apiResID)
	assert.NoError(t, err)
	assert.Equal(t, userID, con.UserID)

	// Hit GetConsent
	con2, err := cachedRepo.GetConsent(ctx, userID, clientID, &apiResID)
	assert.NoError(t, err)
	assert.Equal(t, userID, con2.UserID)

	// GetConsent nil
	mockRepo.On("GetConsent", ctx, userID, clientID, (*uuid.UUID)(nil)).Return((*domain.Consent)(nil), nil).Once()
	con3, err := cachedRepo.GetConsent(ctx, userID, clientID, nil)
	assert.NoError(t, err)
	assert.Nil(t, con3)

	mockRepo.AssertExpectations(t)
}

func TestCachedClientRepository_Mutations(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockClientRepository)
	cachedRepo := NewCachedClientRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	client := &domain.Client{ID: uuid.New(), ClientID: "pub-id"}
	orgID := uuid.New()

	// Update (invalidates cache)
	mockRepo.On("GetClientByID", ctx, client.ID).Return(client, nil).Once()
	mockRepo.On("Update", ctx, client).Return(nil).Once()
	err := cachedRepo.Update(ctx, client)
	assert.NoError(t, err)

	// Delete (invalidates cache)
	mockRepo.On("GetClientByID", ctx, client.ID).Return(client, nil).Once()
	mockRepo.On("Delete", ctx, client.ID, &orgID).Return(nil).Once()
	err = cachedRepo.Delete(ctx, client.ID, &orgID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestCachedClientRepository_PassThroughs(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()

	mockRepo := new(mockClientRepository)
	cachedRepo := NewCachedClientRepository(mockRepo, rdb, 5*time.Minute)

	ctx := context.Background()
	client := &domain.Client{ID: uuid.New()}
	orgID := uuid.New()

	// RegisterClient
	mockRepo.On("RegisterClient", ctx, client).Return(nil).Once()
	err := cachedRepo.RegisterClient(ctx, client)
	assert.NoError(t, err)

	// List
	pg := Pagination{}
	mockRepo.On("List", ctx, pg, &orgID).Return([]*domain.Client{client}, 1, nil).Once()
	clArgs, ct, err := cachedRepo.List(ctx, pg, &orgID)
	assert.NoError(t, err)
	assert.Len(t, clArgs, 1)
	assert.Equal(t, 1, ct)

	// SaveConsent
	apiResID := uuid.New()
	consent := &domain.Consent{UserID: uuid.New(), ClientID: client.ID, APIResourceID: &apiResID}
	mockRepo.On("SaveConsent", ctx, consent).Return(nil).Once()
	err = cachedRepo.SaveConsent(ctx, consent)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
