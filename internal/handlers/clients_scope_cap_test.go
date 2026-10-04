package handlers

import (
	"net/http"
	"testing"
)

// An org_admin cannot hand an application more than it holds itself. A client's
// scope names what the app may ask for; a scope of the IdP's own catalogue that
// the creating admin does not hold (keys:rotate, orgs:create, ...) is refused,
// while identity scopes and an organization's own API scopes pass.

func TestCreateClient_ScopeIsCappedAtTheCreatorsOwn(t *testing.T) {
	create := func(t *testing.T, scope string) (int, int, map[string]any) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", `{"name":"app","redirect_uris":["https://app.example.com/cb"],"scope":"`+scope+`"}`)
		return st, len(e.repo.rows), m
	}

	t.Run("a scope the admin does not hold is refused, nothing created", func(t *testing.T) {
		for _, scope := range []string{"openid keys:rotate", "orgs:create", "system:config:update", "identuum-admin:admin", "mcp:access_admin", "users:read orgs:delete"} {
			st, rows, m := create(t, scope)
			if st != http.StatusBadRequest || m["error"] != "invalid_scope" || rows != 0 {
				t.Errorf("scope %q = %d %v rows=%d; want 400 invalid_scope and nothing created", scope, st, m, rows)
			}
		}
	})
	t.Run("identity scopes, held admin scopes and an organization's own API scopes pass", func(t *testing.T) {
		for _, scope := range []string{"openid profile email offline_access", "openid users:read clients:read", "openid orders:read orders:write", ""} {
			if st, _, m := create(t, scope); st != http.StatusCreated {
				t.Errorf("scope %q = %d %v; want 201", scope, st, m)
			}
		}
	})
}

func TestUpdateClient_ScopeIsCappedAtTheCreatorsOwn(t *testing.T) {
	t.Run("widening to a scope the admin does not hold is refused, unchanged", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
		id := e.seedClient(false, false)
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"scope":"openid keys:rotate"}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_scope" || e.repo.rows[id].Scope != "openid" {
			t.Errorf("= %d %v scope=%q; want 400 invalid_scope and unchanged", st, m, e.repo.rows[id].Scope)
		}
	})
	t.Run("an allowed scope is stored", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
		id := e.seedClient(false, false)
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"scope":"openid orders:read users:read"}`)
		if st != http.StatusOK || e.repo.rows[id].Scope != "openid orders:read users:read" {
			t.Errorf("= %d %v scope=%q; want 200 and stored", st, m, e.repo.rows[id].Scope)
		}
	})
	t.Run("an update that leaves the scope alone is not judged on it", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
		id := e.seedClient(false, false)
		e.repo.rows[id].Scope = "openid keys:rotate"
		if st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"name":"renamed"}`); st != http.StatusOK {
			t.Errorf("rename of an app whose stored scope predates the cap = %d %v; want 200", st, m)
		}
	})
}
