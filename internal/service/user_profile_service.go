// Package service — UserProfileService owns the optional OIDC profile row
// (THE-PROFILE-CLAIMS): read for claim emission, patch for the self-service
// and admin user surfaces. Validation lives in the domain (UserProfilePatch.
// Apply); this service only sequences read → apply → upsert.
package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// UserProfileService is the façade over user_profiles.
type UserProfileService struct {
	repo repository.UserProfileRepository
}

// NewUserProfileService constructs the service. repo must be non-nil.
func NewUserProfileService(report *lifecycle.StartupReport, repo repository.UserProfileRepository) *UserProfileService {
	if repo == nil {
		report.Fatal("NewUserProfileService", "service: NewUserProfileService requires a non-nil UserProfileRepository")
	}
	return &UserProfileService{repo: repo}
}

// Get returns the user's profile row, or (nil, nil) when the user has never
// set a profile field.
func (s *UserProfileService) Get(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	if userID == uuid.Nil {
		return nil, nil
	}
	return s.repo.Get(ctx, userID)
}

// Apply merges patch into the user's profile (creating the row on first
// write), validates every touched field (domain.ErrUserProfileInvalid names
// the field), and persists. An empty patch returns the current row without
// writing.
func (s *UserProfileService) Apply(ctx context.Context, userID uuid.UUID, patch domain.UserProfilePatch) (*domain.UserProfile, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrUserNotFound
	}
	current, err := s.repo.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if patch.IsEmpty() {
		return current, nil
	}
	next, err := patch.Apply(current, userID)
	if err != nil {
		return nil, err
	}
	return s.repo.Upsert(ctx, next)
}
