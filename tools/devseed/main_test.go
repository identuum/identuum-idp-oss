package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// devseed walks the authority model as the product demands it. Two of its
// rulings changed the calls it must make:
//
//   - D-025: a site administrator no longer edits a tenant user, so it cannot
//     mark the first org_admin verified. That admin is INVITED (a create with no
//     password) and redeems the invite with the known test password, which
//     verifies and activates the account.
//   - D-017: an admin-set password must be changed at first sign-in, which a
//     seed cannot do by hand. The org_user, created WITH a password by its org
//     admin, is created with must_change_password false.

type recordedCall struct {
	method, path string
	body         map[string]any
}

type fakeIdP struct {
	mu    sync.Mutex
	calls []recordedCall
	srv   *httptest.Server
	// createStatus overrides the answer of POST /api/v1/users.
	createStatus int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{createStatus: http.StatusCreated}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{r.Method, r.URL.Path, body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/users":
			w.WriteHeader(f.createStatus)
			if _, hasPassword := body["password"]; hasPassword {
				_, _ = io.WriteString(w, `{"id":"user-pw"}`)
			} else {
				_, _ = io.WriteString(w, `{"user":{"id":"user-invited"},"invite_token":"invite-token-1"}`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/invite":
			_, _ = io.WriteString(w, `{}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) find(method, path string) *recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.calls {
		if f.calls[i].method == method && strings.HasPrefix(f.calls[i].path, path) {
			return &f.calls[i]
		}
	}
	return nil
}

func TestEnsureOrgAdminByInvite_IsInvitedAndRedeemsWithTheKnownPassword(t *testing.T) {
	idp := newFakeIdP(t)
	id, err := ensureOrgAdminByInvite(idp.srv.URL, "site-bearer", orgAdminEmail, orgAdminPass, "org-1")
	if err != nil || id != "user-invited" {
		t.Fatalf("= %q, %v; want the invited user's id", id, err)
	}

	create := idp.find(http.MethodPost, "/api/v1/users")
	if create == nil {
		t.Fatal("no user was created")
	}
	if _, set := create.body["password"]; set {
		t.Error("the first org_admin is invited, not created with a password a site administrator would then have to verify")
	}
	if create.body["role"] != "org_admin" || create.body["organization_id"] != "org-1" || create.body["email"] != orgAdminEmail {
		t.Errorf("create body = %v; want the org_admin of org-1", create.body)
	}
	redeem := idp.find(http.MethodPost, "/api/v1/auth/invite")
	if redeem == nil || redeem.body["token"] != "invite-token-1" || redeem.body["password"] != orgAdminPass {
		t.Errorf("redeem = %+v; want the invite token redeemed with the known test password", redeem)
	}
	if idp.find(http.MethodPut, "/api/v1/users/") != nil {
		t.Error("a site administrator must not edit the tenant user (D-025)")
	}
}

func TestEnsureOrgAdminByInvite_AlreadySeededIsNotAnError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.createStatus = http.StatusConflict
	id, err := ensureOrgAdminByInvite(idp.srv.URL, "site-bearer", orgAdminEmail, orgAdminPass, "org-1")
	if err != nil || id != "" {
		t.Errorf("= %q, %v; want an empty id and no error (re-running the seed is safe)", id, err)
	}
	if idp.find(http.MethodPost, "/api/v1/auth/invite") != nil {
		t.Error("nothing to redeem when the admin already exists")
	}
}

func TestEnsureUser_AdminSetPasswordIsNotForcedToChange(t *testing.T) {
	idp := newFakeIdP(t)
	if _, err := ensureUser(idp.srv.URL, "admin-bearer", orgUserEmail, orgUserPass, "org_user", ""); err != nil {
		t.Fatalf("ensureUser: %v", err)
	}
	create := idp.find(http.MethodPost, "/api/v1/users")
	if create == nil || create.body["must_change_password"] != false {
		t.Errorf("create body = %v; want must_change_password false so the seeded user can sign in by hand", create)
	}
	if put := idp.find(http.MethodPut, "/api/v1/users/user-pw"); put == nil || put.body["email_verified"] != true {
		t.Errorf("verify call = %+v; the org admin marks its own user verified", put)
	}
}
