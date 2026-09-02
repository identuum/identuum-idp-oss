package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Domain Errors
var (
	ErrRefreshTokenReuse = errors.New("secure refresh token reuse detected")
)

// Session represents a user authentication session domain model
// This is the NEW pattern - pure domain model without database concerns
type Session struct {
	CreatedAt          time.Time
	ExpiresAt          time.Time
	TokenSelector      *uuid.UUID
	TokenValidatorHash *string
	// PrevValidatorHash and PrevRotatedAt (migration 0021, P0-12b) record
	// the immediately-preceding validator hash and the DB-clock instant
	// it was superseded by a rotation. Used ONLY to distinguish a benign
	// concurrent racer (presents the just-superseded hash within the
	// grace window — see sessionRotationGraceWindow) from genuine
	// refresh-token reuse (any other stale hash). Both nil until a
	// session's first rotation; paired by chk_sessions_prev_validator_paired.
	PrevValidatorHash *string
	PrevRotatedAt     *time.Time
	LastUsedAt        *time.Time
	RevokedAt         *time.Time
	RevokedReason     *string
	Token             string
	Acr               string
	Amr               []string
	// ClientID identifies the OAuth client to which this session's refresh
	// token was issued (set during OIDC /authorize → /token exchange). Nil
	// for admin-UI logins and for any session created before migration 0046.
	// The /auth/revoke handler enforces RFC 7009 §2.1 client-authentication
	// binding against this value (RFC 6749 §10.4 cross-client replay defence).
	ClientID *string
	// LastACRUpliftAt and LastACRUpliftValue track the most recent ACR
	// step-up event on this session (migration 0063). When both are
	// non-nil, EffectiveACR / EffectiveAuthTime return the step-up
	// values; when both are nil, they fall back to the original
	// session's Acr and CreatedAt. The DB CHECK chk_sessions_acr_uplift_paired
	// keeps these two fields in sync — either both NULL or both
	// non-NULL, never one of each.
	LastACRUpliftAt    *time.Time
	LastACRUpliftValue *string
	// IPAddress and UserAgent capture session-origin metadata (migration 0015).
	// Both are optional (nil for sessions created before the migration).
	IPAddress  *string
	UserAgent  *string
	ID         uuid.UUID
	UserID     uuid.UUID
	IsValid    bool
	RememberMe bool
}

// EffectiveACR returns the ACR rung that should be considered current
// for this session — the most recent step-up value if one occurred,
// otherwise the session's original ACR.
func (s *Session) EffectiveACR() string {
	if s.LastACRUpliftValue != nil {
		return *s.LastACRUpliftValue
	}
	return s.Acr
}

// EffectiveAuthTime returns the time-of-authentication that produced
// the current effective ACR — the step-up timestamp if one occurred,
// otherwise the session's CreatedAt. Used as the input to upstream
// ACR floor freshness checks.
func (s *Session) EffectiveAuthTime() time.Time {
	if s.LastACRUpliftAt != nil {
		return *s.LastACRUpliftAt
	}
	return s.CreatedAt
}

// EffectiveAMR returns the authentication methods that produced the
// current effective ACR (THE-HONEST-ACR). A TOTP step-up appends "otp"
// (RFC 8176) to the session's original methods, so amr never claims less
// than acr and never more than what was performed.
func (s *Session) EffectiveAMR() []string {
	out := append([]string(nil), s.Amr...)
	if s.LastACRUpliftValue != nil && *s.LastACRUpliftValue == "urn:identuum:loa:mfa" {
		for _, m := range out {
			if m == "otp" {
				return out
			}
		}
		out = append(out, "otp")
	}
	return out
}

// RecordACRUplift atomically updates the step-up tracking columns on
// an in-memory Session value. Persistence is the caller's job; this
// helper exists so the step-up service has a single source of truth
// for the "set both fields together" invariant pinned by the DB CHECK.
func (s *Session) RecordACRUplift(now time.Time, acr string) {
	t := now
	v := acr
	s.LastACRUpliftAt = &t
	s.LastACRUpliftValue = &v
}

// Validate performs business logic validation on the Session
func (s *Session) Validate() error {
	if s.UserID == uuid.Nil {
		return errors.New("user_id is required")
	}

	if s.TokenSelector == nil {
		return errors.New("token_selector is required")
	}

	if s.TokenValidatorHash == nil || *s.TokenValidatorHash == "" {
		return errors.New("token_validator_hash is required")
	}

	if s.ExpiresAt.Before(s.CreatedAt) {
		return errors.New("expires_at must be after created_at")
	}

	return nil
}

// IsExpired checks if the session has expired.
// now must be injected by the caller (service layer).
func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

// CanBeUsed checks if session can be used for authentication.
// now must be injected by the caller (service layer).
func (s *Session) CanBeUsed(now time.Time) (bool, string) {
	if !s.IsValid {
		return false, "session is not valid"
	}

	if s.RevokedAt != nil {
		reason := "session revoked"
		if s.RevokedReason != nil {
			reason = *s.RevokedReason
		}
		return false, reason
	}

	if s.IsExpired(now) {
		return false, "session expired"
	}

	return true, ""
}

// Revoke marks the session as revoked.
// now must be injected by the caller (service layer).
func (s *Session) Revoke(now time.Time, reason string) {
	s.RevokedAt = &now
	s.RevokedReason = &reason
	s.IsValid = false
}

// UpdateLastUsed updates the last used timestamp.
// now must be injected by the caller (service layer).
func (s *Session) UpdateLastUsed(now time.Time) {
	s.LastUsedAt = &now
}

// TimeUntilExpiry returns the duration until the session expires
func (s *Session) TimeUntilExpiry() time.Duration {
	return time.Until(s.ExpiresAt)
}

// SessionValidationInfo contains session data along with user and organization status
// Used for efficient validation in middleware with a single database query
type SessionValidationInfo struct {
	Session        *Session
	UserActive     bool
	UserDeleted    bool
	OrgActive      bool
	OrgDeleted     bool
	OrganizationID uuid.UUID
}

// CanBeUsedForAuth checks if session can be used considering user and org status.
// now must be injected by the caller (middleware/service layer).
func (svi *SessionValidationInfo) CanBeUsedForAuth(now time.Time) (bool, string) {
	if svi.Session == nil {
		return false, "session not found"
	}

	// Check session validity first
	canUse, reason := svi.Session.CanBeUsed(now)
	if !canUse {
		return false, reason
	}

	// Check user status
	if svi.UserDeleted {
		return false, "user account deleted"
	}
	if !svi.UserActive {
		return false, "user account disabled"
	}

	// Check organization status
	if svi.OrgDeleted {
		return false, "organization deleted"
	}
	if !svi.OrgActive {
		return false, "organization disabled"
	}

	return true, ""
}
