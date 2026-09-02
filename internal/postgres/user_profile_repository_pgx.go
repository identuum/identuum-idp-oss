package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxUserProfileRepository implements repository.UserProfileRepository
// against user_profiles (migration 0035, THE-PROFILE-CLAIMS).
type PgxUserProfileRepository struct {
	db DBTX
}

// NewPgxUserProfileRepository constructs the repo.
func NewPgxUserProfileRepository(db DBTX) *PgxUserProfileRepository {
	return &PgxUserProfileRepository{db: db}
}

var _ repository.UserProfileRepository = (*PgxUserProfileRepository)(nil)

const userProfileColumns = `user_id, given_name, family_name, middle_name, nickname, preferred_username,
       profile, picture, website, gender, birthdate, zoneinfo, locale,
       phone_number, address_formatted, address_street_address, address_locality,
       address_region, address_postal_code, address_country, created_at, updated_at`

// Get returns the row or (nil, nil).
func (r *PgxUserProfileRepository) Get(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	if userID == uuid.Nil {
		return nil, nil
	}
	q := `SELECT ` + userProfileColumns + ` FROM user_profiles WHERE user_id = $1`
	out, err := scanUserProfile(r.db.QueryRow(ctx, q, userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get user_profiles: %w", err)
	}
	return out, nil
}

// Upsert writes every profile column; NULL clears. updated_at is stamped
// by the database so `updated_at` at userinfo reflects this write.
func (r *PgxUserProfileRepository) Upsert(ctx context.Context, p *domain.UserProfile) (*domain.UserProfile, error) {
	if p == nil || p.UserID == uuid.Nil {
		return nil, errors.New("postgres: UserProfile.UserID required")
	}
	q := `
INSERT INTO user_profiles (
    user_id, given_name, family_name, middle_name, nickname, preferred_username,
    profile, picture, website, gender, birthdate, zoneinfo, locale,
    phone_number, address_formatted, address_street_address, address_locality,
    address_region, address_postal_code, address_country, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW(), NOW())
ON CONFLICT (user_id) DO UPDATE SET
    phone_number = EXCLUDED.phone_number,
    address_formatted = EXCLUDED.address_formatted,
    address_street_address = EXCLUDED.address_street_address,
    address_locality = EXCLUDED.address_locality,
    address_region = EXCLUDED.address_region,
    address_postal_code = EXCLUDED.address_postal_code,
    address_country = EXCLUDED.address_country,
    given_name = EXCLUDED.given_name,
    family_name = EXCLUDED.family_name,
    middle_name = EXCLUDED.middle_name,
    nickname = EXCLUDED.nickname,
    preferred_username = EXCLUDED.preferred_username,
    profile = EXCLUDED.profile,
    picture = EXCLUDED.picture,
    website = EXCLUDED.website,
    gender = EXCLUDED.gender,
    birthdate = EXCLUDED.birthdate,
    zoneinfo = EXCLUDED.zoneinfo,
    locale = EXCLUDED.locale,
    updated_at = NOW()
RETURNING ` + userProfileColumns
	out, err := scanUserProfile(r.db.QueryRow(ctx, q,
		p.UserID, p.GivenName, p.FamilyName, p.MiddleName, p.Nickname, p.PreferredUsername,
		p.Profile, p.Picture, p.Website, p.Gender, p.Birthdate, p.Zoneinfo, p.Locale,
		p.PhoneNumber, p.AddressFormatted, p.AddressStreetAddress, p.AddressLocality,
		p.AddressRegion, p.AddressPostalCode, p.AddressCountry,
	))
	if err != nil {
		return nil, fmt.Errorf("postgres: upsert user_profiles: %w", err)
	}
	return out, nil
}

func scanUserProfile(row pgx.Row) (*domain.UserProfile, error) {
	var p domain.UserProfile
	if err := row.Scan(
		&p.UserID, &p.GivenName, &p.FamilyName, &p.MiddleName, &p.Nickname, &p.PreferredUsername,
		&p.Profile, &p.Picture, &p.Website, &p.Gender, &p.Birthdate, &p.Zoneinfo, &p.Locale,
		&p.PhoneNumber, &p.AddressFormatted, &p.AddressStreetAddress, &p.AddressLocality,
		&p.AddressRegion, &p.AddressPostalCode, &p.AddressCountry,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}
