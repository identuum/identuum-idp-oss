package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// failingRefreshRevoker makes the reset's "end every other sign-in" step fail.
type failingRefreshRevoker struct{ calls int }

func (f *failingRefreshRevoker) RevokeAllForUser(context.Context, uuid.UUID) (int64, error) {
	f.calls++
	return 0, errors.New("simulated outage")
}

// UI-0913-B-REST-REVIEW Q1 (a): a redeem whose password is set but whose old
// sessions could not be ended answers its own code, sessions_not_ended, with
// the plain words, so the console can show "password set" with a warning
// instead of "Try again". The link is spent: a retry answers invalid_token.
func TestD9_RedeemSessionsNotEndedHasItsOwnCode(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rev := &failingRefreshRevoker{}
	w.svc.WithRefreshTokenRevoker(rev)
	oldHash := w.users.byID[w.ids["member"]].PasswordHash

	rec, body := w.issue(d9AdminA, "member")
	if rec.Code != http.StatusOK {
		t.Fatalf("issue = %d %v; want 200", rec.Code, body["error"])
	}
	tok := tokenOf(t, body)

	b, _ := json.Marshal(map[string]string{"token": tok, "new_password": d9NewPassword})
	req := httptest.NewRequest(http.MethodPost, d9Spec().consumePath, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	w.engine.ServeHTTP(res, req)

	if rev.calls != 1 {
		t.Fatalf("PREMISE: the refresh-token revoker ran %d times; want 1", rev.calls)
	}
	var got map[string]string
	_ = json.Unmarshal(res.Body.Bytes(), &got)
	if res.Code != http.StatusInternalServerError || got["error"] != "sessions_not_ended" {
		t.Fatalf("redeem with a failed session end = %d %q; want 500 sessions_not_ended", res.Code, got["error"])
	}
	const want = "Your new password is set, but your other sign-ins could not be ended. Sign in with the new password and ask your administrator to end your other sessions."
	if got["message"] != want {
		t.Errorf("message = %q; want %q", got["message"], want)
	}
	if w.users.byID[w.ids["member"]].PasswordHash == oldHash {
		t.Errorf("the password must be set even though the sessions survive")
	}
	if st, code := w.consume(tok, d9NewPassword); st != http.StatusBadRequest || code != "invalid_token" {
		t.Errorf("retry = %d %q; want 400 invalid_token (the link is spent)", st, code)
	}
}
