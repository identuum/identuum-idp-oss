package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// mfa_self_enroll.go — FUNC-M1: a signed-in user adds an authenticator from
// account settings, the contract identuum-idp-ce serves on the same paths
// (/api/v1/mfa/setup/initiate + /complete). Initiate takes the current
// password, the one proof a user with no factor holds (a session alone would
// let a stolen cookie arm the thief's authenticator); a wrong password counts
// on the per-user proof budget the other proof routes share, so a spent
// budget answers sign-in's wait. The candidate secret lives on a pending
// enrol-kind row bound to the user, and complete finds the user's newest live
// one in the database (the console reaches these routes through the browser
// boundary, which forwards no cookie, so no handle travels on the wire; until
// OSS-HARDEN-1 the service remembered the row in process memory, and a
// restart meant starting again). The recovery codes are minted at complete
// and shown once.

var (
	// ErrMFASelfAlreadyEnrolled — the user already has an authenticator.
	ErrMFASelfAlreadyEnrolled = errors.New("service: mfa already enrolled")
	// ErrMFASelfProofInvalid — the password was absent, wrong, or the account
	// has no local password; one cause-neutral refusal.
	ErrMFASelfProofInvalid = errors.New("service: mfa self-enrolment proof invalid")
)

// MFASelfEnrollStart is what InitiateSelf returns: the one-time setup
// material.
type MFASelfEnrollStart struct {
	Secret     string
	OtpauthURL string
	ExpiresAt  time.Time
}

// InitiateSelf verifies the user's current password and starts an enrolment.
func (s *MFAEnrollmentService) InitiateSelf(ctx context.Context, userID uuid.UUID, password string) (*MFASelfEnrollStart, error) {
	user, err := s.liveUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.MFAEnabled {
		return nil, ErrMFASelfAlreadyEnrolled
	}
	release := s.proofFailures.Hold(user.ID)
	defer release()
	if spent, wait := budgetWait(ctx, s.proofFailures, user.ID); spent {
		if wait != nil {
			return nil, wait
		}
		return nil, ErrMFASelfProofInvalid
	}
	if !s.localPasswordOK(ctx, user, password) {
		s.proofFailures.Record(ctx, user.ID)
		return nil, ErrMFASelfProofInvalid
	}
	row, err := s.CreatePending(ctx, user, domain.MFAPendingKindEnroll, false)
	if err != nil {
		return nil, err
	}
	res, err := s.Initiate(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	return &MFASelfEnrollStart{Secret: res.Secret, OtpauthURL: res.OtpauthURL, ExpiresAt: res.ExpiresAt}, nil
}

// ErrMFASelfNotStarted — CompleteSelf found no enrolment of the user to
// complete: none was started, or it expired or was used.
var ErrMFASelfNotStarted = errors.New("service: mfa self-enrolment not started")

// CompleteSelf verifies the code against the candidate secret of the user's
// newest self-enrolment, enables MFA and returns fresh recovery codes, once.
// A wrong code leaves the enrolment open until it expires.
func (s *MFAEnrollmentService) CompleteSelf(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	user, err := s.liveUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.MFAEnabled {
		return nil, ErrMFASelfAlreadyEnrolled
	}
	row, err := s.pending.GetLatestLiveEnroll(ctx, user.ID, s.now())
	if errors.Is(err, repository.ErrMFAPendingSessionNotFound) || (err == nil && (row == nil || row.UserID != user.ID)) {
		return nil, ErrMFASelfNotStarted
	}
	if err != nil {
		return nil, fmt.Errorf("service: mfa self-enrolment lookup: %w", err)
	}
	codes, err := generateRecoveryCodes(s.codeCount, s.codeBytes)
	if err != nil {
		return nil, fmt.Errorf("service: mfa self-enrolment recovery codes: %w", err)
	}
	if _, err := s.complete(ctx, row.ID, strings.TrimSpace(code), hashRecoveryCodes(codes)); err != nil {
		if errors.Is(err, ErrMFAEnrollmentExpired) || errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) || errors.Is(err, ErrMFAEnrollmentNotFound) {
			return nil, ErrMFASelfNotStarted
		}
		return nil, err
	}
	return codes, nil
}

func (s *MFAEnrollmentService) liveUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	if userID == uuid.Nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil || user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	return user, nil
}

// localPasswordOK reads the hash through GetByIDWithOrg, the read the
// password change uses: GetByID does not select it.
func (s *MFAEnrollmentService) localPasswordOK(ctx context.Context, user *domain.User, password string) bool {
	if password == "" {
		return false
	}
	withHash, err := s.users.GetByIDWithOrg(ctx, user.ID)
	if err != nil || withHash == nil || withHash.ID != user.ID {
		return false
	}
	user = withHash
	if strings.TrimSpace(user.PasswordHash) == "" {
		return false
	}
	if user.AuthSource != "" && user.AuthSource != domain.AuthSourceLocal {
		return false
	}
	return s.users.VerifyPassword(ctx, password, user.PasswordHash) == nil
}
