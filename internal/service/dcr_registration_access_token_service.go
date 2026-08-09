package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// DCRRegistrationAccessTokenService manages the RFC 7592 §2
// registration access token (RAT) bound to a DCR-created OAuth
// client. The DCR /register handler calls Mint right after the
// client is persisted; the RFC 7592 GET/PUT/DELETE handler calls
// Authenticate on every request; the RFC 7592 DELETE handler
// calls Revoke alongside the client deletion.
type DCRRegistrationAccessTokenService struct {
	repo repository.DCRClientRegistrationTokenRepository
}

// NewDCRRegistrationAccessTokenService builds the service. repo
// MUST be non-nil; passing nil is a bootstrap bug and panics.
func NewDCRRegistrationAccessTokenService(report *lifecycle.StartupReport, repo repository.DCRClientRegistrationTokenRepository) *DCRRegistrationAccessTokenService {
	if repo == nil {
		report.Fatal("NewDCRRegistrationAccessTokenService", "service: NewDCRRegistrationAccessTokenService requires a non-nil repository")
	}
	return &DCRRegistrationAccessTokenService{repo: repo}
}

// ErrRATInvalid is the opaque sentinel returned by Authenticate
// for any failure mode the service does not want to disambiguate
// on the wire (no RAT row / wrong hash). The RFC 7592 handler
// MUST map this to a single generic 401 response.
var ErrRATInvalid = errors.New("service: dcr registration access token invalid")

// Mint generates a fresh 256-bit opaque RAT, hashes it, stores
// the hash on a fresh (or replaced) row for clientID, and
// returns the raw RAT exactly once. The caller MUST emit the
// raw RAT to the registering RP in the DCR response body and
// then drop it.
//
// Rotation is implicit: a second Mint call for the same client
// REPLACES the prior row (the prior RAT is invalidated
// immediately). The handler that calls Mint as part of an
// update flow MUST audit the rotation; the rotation itself is
// a single repo round-trip.
func (s *DCRRegistrationAccessTokenService) Mint(ctx context.Context, clientID uuid.UUID) (string, error) {
	if clientID == uuid.Nil {
		return "", fmt.Errorf("service: Mint requires non-nil client_id")
	}
	raw, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("service: RAT generation failed: %w", err)
	}
	hash := crypto.HashSecret(raw)
	if _, err := s.repo.Upsert(ctx, clientID, hash); err != nil {
		return "", err
	}
	return raw, nil
}

// Authenticate verifies that rawRAT is the active token for
// clientID. Returns nil on success; ErrRATInvalid for every
// failure mode (missing row / wrong hash / empty inputs).
//
// rawRAT is hashed before lookup. The raw RAT is NEVER logged
// or persisted.
func (s *DCRRegistrationAccessTokenService) Authenticate(ctx context.Context, clientID uuid.UUID, rawRAT string) error {
	if clientID == uuid.Nil || rawRAT == "" {
		return ErrRATInvalid
	}
	hash := crypto.HashSecret(rawRAT)
	if _, err := s.repo.LookupByClientIDAndHash(ctx, clientID, hash); err != nil {
		if errors.Is(err, repository.ErrDCRClientRegistrationTokenNotFound) {
			return ErrRATInvalid
		}
		return err
	}
	return nil
}

// IsManaged reports whether clientID was created via DCR
// (i.e. has an active RAT row). The handler uses this to
// distinguish DCR-created clients from site-admin-created
// clients before exposing the RFC 7592 surface.
func (s *DCRRegistrationAccessTokenService) IsManaged(ctx context.Context, clientID uuid.UUID) (bool, error) {
	_, err := s.repo.GetByClientID(ctx, clientID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, repository.ErrDCRClientRegistrationTokenNotFound) {
		return false, nil
	}
	return false, err
}

// Revoke removes the RAT row for clientID. Idempotent.
func (s *DCRRegistrationAccessTokenService) Revoke(ctx context.Context, clientID uuid.UUID) error {
	return s.repo.DeleteByClientID(ctx, clientID)
}
