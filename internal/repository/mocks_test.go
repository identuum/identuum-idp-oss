package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmailAndOrgID(ctx context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	args := m.Called(ctx, orgID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByExternalID(ctx context.Context, orgID uuid.UUID, externalID string) (*domain.User, error) {
	args := m.Called(ctx, orgID, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, id uuid.UUID, orgID uuid.UUID, opts UpdateUserOptions) (*domain.User, error) {
	args := m.Called(ctx, id, orgID, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

func (m *MockUserRepository) Undelete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts ListUserOptions) ([]*domain.User, int, error) {
	args := m.Called(ctx, orgID, opts)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}

func (m *MockUserRepository) CountByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	args := m.Called(ctx, orgID)
	return args.Int(0), args.Error(1)
}

func (m *MockUserRepository) CountOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	args := m.Called(ctx, orgID)
	return args.Int(0), args.Error(1)
}

func (m *MockUserRepository) CountOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	args := m.Called(ctx, orgIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uuid.UUID]int), args.Error(1)
}

func (m *MockUserRepository) CountVerifiedOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	args := m.Called(ctx, orgID)
	return args.Int(0), args.Error(1)
}

func (m *MockUserRepository) CountVerifiedOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	args := m.Called(ctx, orgIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uuid.UUID]int), args.Error(1)
}

func (m *MockUserRepository) VerifyPassword(ctx context.Context, password, hash string) error {
	args := m.Called(ctx, password, hash)
	return args.Error(0)
}

func (m *MockUserRepository) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepository) GetUserOrganization(ctx context.Context, userID uuid.UUID) (*domain.Organization, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockUserRepository) UpdateOrganizationID(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	args := m.Called(ctx, id, orgID)
	return args.Error(0)
}

// MockOrganizationRepository is a mock implementation of OrganizationRepository
type MockOrganizationRepository struct {
	mock.Mock
}

func (m *MockOrganizationRepository) Create(ctx context.Context, org *domain.Organization) (*domain.Organization, error) {
	args := m.Called(ctx, org)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) CreateWithAdmin(ctx context.Context, org *domain.Organization, adminUser *domain.User) (*domain.Organization, *domain.User, error) {
	args := m.Called(ctx, org, adminUser)
	var retOrg *domain.Organization
	var retUser *domain.User
	if args.Get(0) != nil {
		retOrg = args.Get(0).(*domain.Organization)
	}
	if args.Get(1) != nil {
		retUser = args.Get(1).(*domain.User)
	}
	return retOrg, retUser, args.Error(2)
}

func (m *MockOrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) GetByDomain(ctx context.Context, domainName string) (*domain.Organization, error) {
	args := m.Called(ctx, domainName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) Update(ctx context.Context, id uuid.UUID, opts UpdateOrganizationOptions) (*domain.Organization, error) {
	args := m.Called(ctx, id, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOrganizationRepository) Undelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOrganizationRepository) List(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error) {
	args := m.Called(ctx, filter, pagination, sort)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.Organization), args.Int(1), args.Error(2)
}

func (m *MockOrganizationRepository) CountUsers(ctx context.Context, id uuid.UUID) (int, error) {
	args := m.Called(ctx, id)
	return args.Int(0), args.Error(1)
}

func (m *MockOrganizationRepository) CountSessions(ctx context.Context, id uuid.UUID) (int, error) {
	args := m.Called(ctx, id)
	return args.Int(0), args.Error(1)
}

func (m *MockOrganizationRepository) GetDetails(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*domain.Organization), args.Get(1).(map[string]int), args.Error(2)
}

// AdminOrganizationRepository methods
func (m *MockOrganizationRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Organization), args.Error(1)
}

func (m *MockOrganizationRepository) GetDetailsAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*domain.Organization), args.Get(1).(map[string]int), args.Error(2)
}

func (m *MockOrganizationRepository) ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.Organization, int, error) {
	args := m.Called(ctx, pagination)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.Organization), args.Int(1), args.Error(2)
}

func (m *MockOrganizationRepository) ListAll(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error) {
	args := m.Called(ctx, filter, pagination, sort)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.Organization), args.Int(1), args.Error(2)
}

func (m *MockOrganizationRepository) HardDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOrganizationRepository) UpdateID(ctx context.Context, oldID, newID uuid.UUID) error {
	args := m.Called(ctx, oldID, newID)
	return args.Error(0)
}
