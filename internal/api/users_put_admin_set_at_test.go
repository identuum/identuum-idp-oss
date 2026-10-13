package api

// G2 + Q-G2b (a): a password an admin sets through PUT /api/v1/users/:id with
// the must-change flag stores when the admin set it, in the SAME repository
// write as the hash and the flag; must_change_password:false writes the flag
// false and clears the time (a lasting password). A PUT without a password
// touches neither.
//
// RED AT COMPILE at 495885c (repository.UpdateUserOptions.AdminPasswordSetAt
// does not exist; see tests/g2/admin_set_password_expiry_test.go for the seam).
// UserService reads time.Now today, so the stamp is checked in a window.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (w *d9World) g2Put(bearer, who, body string) int {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+w.ids[who].String(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	return rec.Code
}

func TestG2_AdminPutPasswordStampsSetTime(t *testing.T) {
	w := newD9World(t, d9UIBase)
	before := time.Now().Add(-time.Second)
	if st := w.g2Put(d9AdminA, "member", `{"password":"Admin-Put-Pass-2026!q"}`); st != http.StatusOK {
		t.Fatalf("PUT password = %d; want 200", st)
	}
	opt := w.users.lastOpt
	if opt == nil || opt.Password == nil {
		t.Fatalf("no repository write carried the password")
	}
	if opt.AdminPasswordSetAt == nil || opt.AdminPasswordSetAt.Before(before) || opt.AdminPasswordSetAt.After(time.Now().Add(time.Second)) {
		t.Errorf("the password write carried AdminPasswordSetAt = %v; want the time of the PUT", opt.AdminPasswordSetAt)
	}
}

func TestG2_AdminPutLastingPasswordClearsSetTime(t *testing.T) {
	w := newD9World(t, d9UIBase)
	if st := w.g2Put(d9AdminA, "member", `{"password":"Admin-Put-Pass-2026!q","must_change_password":false}`); st != http.StatusOK {
		t.Fatalf("PUT password + false = %d; want 200", st)
	}
	opt := w.users.lastOpt
	if opt == nil || opt.AdminPasswordSetAt == nil || !opt.AdminPasswordSetAt.IsZero() {
		t.Errorf("a lasting password did not clear the set time (AdminPasswordSetAt = %v; want pointer to the zero time = NULL)", opt)
	}
}

// Control at the seam (compiles only with the seam): no password, no time.
func TestG2_PutWithoutPasswordLeavesSetTime(t *testing.T) {
	w := newD9World(t, d9UIBase)
	if st := w.g2Put(d9AdminA, "member", `{"name":"Renamed"}`); st != http.StatusOK {
		t.Fatalf("PUT name = %d; want 200", st)
	}
	if opt := w.users.lastOpt; opt == nil || opt.AdminPasswordSetAt != nil {
		t.Errorf("a PUT without a password touched AdminPasswordSetAt")
	}
}
