package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type refreshStatusRepo struct {
	*inMemoryUserSessionRepo
	statusErr   error
	selectorErr error
	missing     bool
	inactive    bool
	rotations   int
}

func (r *refreshStatusRepo) GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error) {
	if r.selectorErr != nil {
		return nil, r.selectorErr
	}
	return r.inMemoryUserSessionRepo.GetByTokenSelector(ctx, selector)
}

func TestRotate_SelectorFailureIsUnavailableNotInvalidGrant(t *testing.T) {
	ctx := context.Background()
	repo := &refreshStatusRepo{inMemoryUserSessionRepo: newSessionRepo()}
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	issued, err := svc.CreateUserSession(ctx, CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatal("fixture session creation failed")
	}
	repo.selectorErr = errors.New("fixture selector store unavailable")
	result, err := svc.RotateRefreshToken(ctx, issued.RefreshToken)
	if result != nil || !errors.Is(err, ErrUserSessionUnavailable) {
		t.Error("selector store failure must refuse refresh as unavailable, not invalid grant")
	}
	if repo.rotations != 0 {
		t.Error("unavailable selector store advanced the refresh token")
	}
}

func (r *refreshStatusRepo) GetSessionWithUserAndOrgStatus(ctx context.Context, id uuid.UUID) (*domain.SessionValidationInfo, error) {
	if r.statusErr != nil || r.missing {
		return nil, r.statusErr
	}
	session, err := r.GetByID(ctx, id)
	return &domain.SessionValidationInfo{Session: session, UserActive: !r.inactive, OrgActive: true}, err
}

func (r *refreshStatusRepo) RotateToken(ctx context.Context, id uuid.UUID, oldHash, newHash string, expires, used time.Time) (*domain.Session, bool, error) {
	r.rotations++
	return r.inMemoryUserSessionRepo.RotateToken(ctx, id, oldHash, newHash, expires, used)
}

func TestRotate_StatusMustBeAvailableBeforeAnyAcceptance(t *testing.T) {
	for _, predecessor := range []bool{false, true} {
		for _, failure := range []string{"store_error", "missing_status", "inactive_user"} {
			name := "current/" + failure
			if predecessor {
				name = "predecessor_in_grace/" + failure
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				repo := &refreshStatusRepo{inMemoryUserSessionRepo: newSessionRepo()}
				svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
				now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
				svc.now = func() time.Time { return now }
				issued, err := svc.CreateUserSession(ctx, CreateUserSessionInput{UserID: uuid.New()})
				if err != nil {
					t.Fatal("fixture session creation failed")
				}
				if predecessor {
					oldHash := *issued.Session.TokenValidatorHash
					if _, err := svc.RotateRefreshToken(ctx, issued.RefreshToken); err != nil {
						t.Fatal("fixture initial rotation failed")
					}
					// Reproduce the persisted predecessor/grace state without a sleep.
					repo.mu.Lock()
					repo.byID[issued.Session.ID].PrevValidatorHash = &oldHash
					repo.byID[issued.Session.ID].PrevRotatedAt = &now
					repo.mu.Unlock()
				}
				repo.rotations = 0
				before, _ := repo.GetByID(ctx, issued.Session.ID)
				switch failure {
				case "store_error":
					repo.statusErr = errors.New("fixture status store unavailable")
				case "missing_status":
					repo.missing = true
				case "inactive_user":
					repo.inactive = true
				}
				result, err := svc.RotateRefreshToken(ctx, issued.RefreshToken)
				if err == nil || result != nil {
					t.Error("refresh accepted without confirmed active account status")
				}
				if failure != "inactive_user" && errors.Is(err, ErrUserSessionInvalidGrant) {
					t.Error("unavailable status was misreported as an invalid grant")
				}
				if repo.rotations != 0 {
					t.Error("unconfirmed account status advanced the refresh token")
				}
				after, _ := repo.GetByID(ctx, issued.Session.ID)
				if *after.TokenValidatorHash != *before.TokenValidatorHash || !after.ExpiresAt.Equal(before.ExpiresAt) {
					t.Error("refused refresh changed its validator or expiry")
				}
			})
		}
	}
}

type refreshLatestStateRepo struct {
	*refreshStatusRepo
	missingSession bool
}

func (r *refreshLatestStateRepo) GetSessionWithUserAndOrgStatus(ctx context.Context, id uuid.UUID) (*domain.SessionValidationInfo, error) {
	info, err := r.refreshStatusRepo.GetSessionWithUserAndOrgStatus(ctx, id)
	if info != nil {
		if r.missingSession {
			info.Session = nil
		} else {
			info.Session.IsValid = false
		}
	}
	return info, err
}

func TestRotate_LatestSessionStateMustAuthorizeAcceptance(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked_after_selector_read", true: "missing_session_state"}[missing], func(t *testing.T) {
			repo := &refreshLatestStateRepo{refreshStatusRepo: &refreshStatusRepo{inMemoryUserSessionRepo: newSessionRepo()}, missingSession: missing}
			svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
			issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
			if err != nil {
				t.Fatal("fixture creation failed")
			}
			result, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
			if err == nil || result != nil {
				t.Error("refresh accepted without an authoritative live session")
			}
			if repo.rotations != 0 {
				t.Error("unconfirmed session reached token rotation")
			}
		})
	}
}
