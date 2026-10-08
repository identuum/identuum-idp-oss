package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// liveSessions counts the user's live sessions.
func (h *callbackHarness) liveSessions(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	live, err := h.sessionRepo.ListActiveByUserID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return len(live)
}

// again re-arms the consumed state so a second callback can run.
func (h *callbackHarness) again(t *testing.T, st domain.OIDCState) {
	t.Helper()
	cp := st
	h.states.byState[h.stateKey] = &cp
}

// F2 (SEC-MFA-REVIEW-2026-10-08): an upstream sign-in into an organization
// that requires MFA made a full session whatever the upstream proved. It
// needs an explicit upstream MFA level; no acr, a password acr, or an
// unrecognised acr is refused with no session.
func TestOIDCCallback_RequiredMFAPolicyNeedsUpstreamMFA(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		acr    any // nil: omitted
		ok     bool
	}{
		{"required, no acr", "required", nil, false},
		{"required, password acr", "required", "0", false},
		{"required, unrecognised acr", "required", "urn:mace:incommon:iap:silver", false},
		{"required, explicit mfa acr", "required", "1", true},
		{"required, phishing-resistant acr", "required", "phishing-resistant-webauthn", true},
		{"optional, no acr", "optional", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			h.orgs.byID[h.orgID].MFAPolicy = tc.policy
			c := h.validClaims()
			if tc.acr == nil {
				delete(c, "acr")
			} else {
				c["acr"] = tc.acr
			}
			*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
			res, err := h.call()
			if tc.ok {
				if err != nil {
					t.Fatalf("HandleCallback: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrCallbackForbidden) || res != nil {
				t.Fatalf("got error %v (a result returned: %v); want ErrCallbackForbidden and no session", err, res != nil)
			}
			for _, u := range h.users.byID {
				if n := h.liveSessions(t, u.ID); n != 0 {
					t.Fatalf("a refused callback left %d session(s)", n)
				}
			}
		})
	}
}

// F3: the callback signed in through an active provider while the
// organization was local_only, and signed in (and linked) an administrator
// matched by email or external ID. Both are refused; the local account is not
// linked. An org_user under idp_only still signs in.
func TestOIDCCallback_AuthPolicyAndAdministratorGuards(t *testing.T) {
	t.Run("local_only organization", func(t *testing.T) {
		h := newCallbackHarness(t)
		h.orgs.byID[h.orgID].AuthPolicy = domain.AuthPolicyLocalOnly
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
		if _, err := h.call(); !errors.Is(err, ErrCallbackForbidden) {
			t.Fatalf("got %v; want ErrCallbackForbidden", err)
		}
		if len(h.users.byID) != 0 {
			t.Fatal("a local_only organization provisioned a user")
		}
	})
	for _, role := range []domain.UserRole{domain.RoleOrgAdmin, domain.RoleSiteAdmin} {
		t.Run(string(role)+" matched by email", func(t *testing.T) {
			h := newCallbackHarness(t)
			admin := &domain.User{ID: uuid.New(), OrganizationID: h.orgID, Email: "alice@example.com", Role: role}
			h.users.byID[admin.ID] = admin
			*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
			if _, err := h.call(); !errors.Is(err, ErrCallbackForbidden) {
				t.Fatalf("got %v; want ErrCallbackForbidden", err)
			}
			if h.users.byID[admin.ID].ExternalID != nil || h.liveSessions(t, admin.ID) != 0 {
				t.Fatal("the administrator was linked or signed in")
			}
		})
	}
	t.Run("org_admin matched by external ID", func(t *testing.T) {
		h := newCallbackHarness(t)
		st := *h.states.byState[h.stateKey]
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
		res, err := h.call()
		if err != nil {
			t.Fatal(err)
		}
		h.users.byID[res.User.ID].Role = domain.RoleOrgAdmin
		h.again(t, st)
		if _, err := h.call(); !errors.Is(err, ErrCallbackForbidden) {
			t.Fatalf("got %v; want ErrCallbackForbidden", err)
		}
	})
	t.Run("org_user under idp_only signs in", func(t *testing.T) {
		h := newCallbackHarness(t)
		h.orgs.byID[h.orgID].AuthPolicy = domain.AuthPolicyIDPOnly
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
		if _, err := h.call(); err != nil {
			t.Fatalf("HandleCallback: %v", err)
		}
	})
}

// F5: an upstream sign-in passed no session limit, so the organization's
// cap never evicted. With a cap of 1, a second sign-in leaves one session.
func TestOIDCCallback_AppliesTheOrganizationSessionLimit(t *testing.T) {
	h := newCallbackHarness(t)
	h.orgs.byID[h.orgID].MaxSessionsPerUser = 1
	st := *h.states.byState[h.stateKey]
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
	res, err := h.call()
	if err != nil {
		t.Fatal(err)
	}
	h.again(t, st)
	if _, err := h.call(); err != nil {
		t.Fatal(err)
	}
	if n := h.liveSessions(t, res.User.ID); n != 1 {
		t.Fatalf("%d live sessions after two sign-ins with a cap of 1; want 1", n)
	}
}
