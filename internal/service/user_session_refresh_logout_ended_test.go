package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-HARDENING-3 item 3: RevokeRefreshTokenSession looks the session up by
// its selector (an ended one answers nil there) and then revokes it. The pgx
// store answers domain.ErrSessionNotFound when that UPDATE matches no row: a
// session another sign-out or an admin ended between the lookup and the
// revocation. That is the state the logout asked for, not a store failure;
// before, it was wrapped as AuthStoreUnavailable("logout-refresh-revoke") and
// HandleLogout answered 503 revocation_unconfirmed for it.

// endedMeanwhileSessionRepo ends the sessions in `lost` under the caller's
// own revocation: the row is revoked by the other writer, and this UPDATE
// matches nothing.
type endedMeanwhileSessionRepo struct {
	*inMemoryUserSessionRepo
	lost map[uuid.UUID]bool
}

func (r *endedMeanwhileSessionRepo) Revoke(ctx context.Context, id, by uuid.UUID, reason string) error {
	if r.lost[id] {
		_ = r.inMemoryUserSessionRepo.Revoke(ctx, id, by, "ended_meanwhile")
		return domain.ErrSessionNotFound
	}
	return r.inMemoryUserSessionRepo.Revoke(ctx, id, by, reason)
}

func TestRevokeRefreshTokenSession_EndedMeanwhileIsNotAStoreError(t *testing.T) {
	repo := &endedMeanwhileSessionRepo{inMemoryUserSessionRepo: newSessionRepo(), lost: map[uuid.UUID]bool{}}
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	repo.lost[issued.Session.ID] = true

	if err := svc.RevokeRefreshTokenSession(context.Background(), issued.RefreshToken); err != nil {
		t.Fatalf("logout of a session ended meanwhile = %v; want nil, the session is ended", err)
	}
	if repo.byID[issued.Session.ID].RevokedAt == nil {
		t.Fatal("the session is not ended")
	}
}

type failingRevokeSessionRepo struct {
	*inMemoryUserSessionRepo
	err error
}

func (r *failingRevokeSessionRepo) Revoke(context.Context, uuid.UUID, uuid.UUID, string) error {
	return r.err
}

func TestRevokeRefreshTokenSession_AStoreFailureStillRefuses(t *testing.T) {
	// Control: any other store error on the revocation is still a store
	// failure the logout cannot confirm.
	repo := &failingRevokeSessionRepo{inMemoryUserSessionRepo: newSessionRepo(), err: errors.New("store unavailable")}
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	if err := svc.RevokeRefreshTokenSession(context.Background(), issued.RefreshToken); !domain.IsAuthStoreUnavailable(err) {
		t.Fatalf("logout with a failing store = %v; want AuthStoreUnavailable", err)
	}
}
