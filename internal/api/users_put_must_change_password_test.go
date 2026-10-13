package api

// Q-B2 (a), owner 2026-10-12: an admin-set password forces a change at next
// sign-in, as D-017 does for create, unless the admin sends
// must_change_password:false. PUT /api/v1/users/:id accepts optional
// must_change_password (*bool, same JSON name as create). With a password:
// RequiresPasswordChange = nil => true, carried in the SAME repository write
// as the password, after the credentials are revoked (revokeBeforeWrite).
// Without a password the flag is untouched; must_change_password alone is 400.
//
// Uses the D9 fixture (users_password_reset_link_route_test.go, same package):
// install both files together.
//
// The sign-in half (the next password sign-in lands on the change step) is
// proven by internal/e2e/admin_put_password_must_change_http_test.go (needs PG).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const qb2Password = "Admin-Put-Pass-2026!q"

func (w *d9World) put(bearer, who, body string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+w.ids[who].String(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// A password set by an admin requires a change by default, in the same write
// as the password, after the revocation.
// RULE: QB2-ADMIN-SET-MUST-CHANGE-1
func TestQB2_AdminPutPasswordRequiresChangeByDefault(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.put(d9AdminA, "member", `{"password":"`+qb2Password+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT password = %d %v; want 200", rec.Code, body["error"])
	}
	opt := w.users.lastOpt
	if opt == nil || opt.Password == nil {
		t.Fatalf("no repository write carried the password")
	}
	if opt.RequiresPasswordChange == nil || !*opt.RequiresPasswordChange {
		t.Errorf("the password write did not set RequiresPasswordChange=true (got %v)", opt.RequiresPasswordChange)
	}
	if body["requires_password_change"] != true {
		t.Errorf("answer requires_password_change = %v; want true", body["requires_password_change"])
	}
	got := strings.Join(*w.order, ",")
	if got != "revoke:user_password_set,update" {
		t.Errorf("order = %q; want the revocation first, then ONE write", got)
	}
}

// must_change_password:false lets the admin-set password stand.
func TestQB2_AdminPutPasswordFalseLetsItStand(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.put(d9AdminA, "member", `{"password":"`+qb2Password+`","must_change_password":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT password + false = %d %v; want 200", rec.Code, body["error"])
	}
	opt := w.users.lastOpt
	if opt == nil || opt.RequiresPasswordChange == nil || *opt.RequiresPasswordChange {
		t.Errorf("the write did not carry RequiresPasswordChange=false (got %v)", opt)
	}
	if body["requires_password_change"] != false {
		t.Errorf("answer requires_password_change = %v; want false", body["requires_password_change"])
	}
}

// Control (green before and after): without a password the flag is untouched.
func TestQB2_PutWithoutPasswordLeavesFlag(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.put(d9AdminA, "member", `{"name":"Renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT name = %d %v; want 200", rec.Code, body["error"])
	}
	if opt := w.users.lastOpt; opt == nil || opt.RequiresPasswordChange != nil {
		t.Errorf("a PUT without a password touched RequiresPasswordChange")
	}
}

// must_change_password without a password is a bad request; nothing is
// written or revoked.
func TestQB2_MustChangeAloneIs400(t *testing.T) {
	for _, v := range []string{"true", "false"} {
		w := newD9World(t, d9UIBase)
		rec, body := w.put(d9AdminA, "member", `{"must_change_password":`+v+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("must_change_password:%s alone = %d %v; want 400", v, rec.Code, body["error"])
		}
		if len(*w.order) != 0 {
			t.Errorf("must_change_password:%s alone wrote or revoked: %v", v, *w.order)
		}
	}
}
