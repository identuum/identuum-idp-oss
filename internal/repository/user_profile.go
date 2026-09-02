package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// UserProfileRepository persists the optional OIDC profile row
// (user_profiles) — THE-PROFILE-CLAIMS. One row per user; absent means
// every profile field is unset.
type UserProfileRepository interface {
	// Get returns the user's profile row, or (nil, nil) when none exists.
	Get(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error)

	// Upsert writes the whole row (insert, or replace every profile column
	// on conflict) and stamps updated_at. Returns the persisted row.
	Upsert(ctx context.Context, p *domain.UserProfile) (*domain.UserProfile, error)
}
