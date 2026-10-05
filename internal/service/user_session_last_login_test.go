package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recordedLogins struct {
	users []uuid.UUID
	err   error
}

func (r *recordedLogins) UpdateLastLogin(_ context.Context, id uuid.UUID) error {
	r.users = append(r.users, id)
	return r.err
}

// FUNC-M15: a sign-in session records last_login_at; a session derived for a
// client from an earlier sign-in does not; a failed write leaves the sign-in
// standing.
func TestCreateUserSession_RecordsLastLoginForASignIn(t *testing.T) {
	rec := &recordedLogins{}
	svc := NewUserSessionService(nil, newSessionRepo(), UserSessionServiceOptions{DefaultTTL: time.Hour}).WithLastLoginRecorder(rec)
	user := uuid.New()
	if _, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: user}); err != nil {
		t.Fatal(err)
	}
	if len(rec.users) != 1 || rec.users[0] != user {
		t.Fatalf("recorded %v; want the signed-in user once", rec.users)
	}
	client := "app-1"
	if _, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: user, ClientID: &client}); err != nil {
		t.Fatal(err)
	}
	if len(rec.users) != 1 {
		t.Errorf("a client-derived session recorded a login")
	}
	rec.err = errors.New("store down")
	if _, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: user}); err != nil {
		t.Errorf("a failed last_login write failed the sign-in: %v", err)
	}
}
