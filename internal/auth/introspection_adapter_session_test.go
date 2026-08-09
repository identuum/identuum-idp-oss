package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TestClaimsToIntrospection_MapsSessionID pins the session_id mapping that the
// CONF-10 userinfo liveness gate DEPENDS on.
//
// Why this test exists, specifically: the gate in internal/handlers/userinfo.go
// fires only when claims.SessionID != uuid.Nil, because a token with no session
// (client-credentials / service-account) has no session liveness to check —
// the same M2M discriminator the bearer middleware applies. That makes this one
// mapping line load-bearing in a way nothing else pins: DELETE IT and every
// token silently looks like M2M, the gate never fires, and the banned-user
// form-field hole reopens.
//
// Verified by mutation before writing this: removing the mapping left
// internal/auth, internal/handlers, internal/api and internal/service ALL
// GREEN. A security control whose off-switch is invisible to the whole suite
// is not controlled.
func TestClaimsToIntrospection_MapsSessionID(t *testing.T) {
	sid := uuid.New()
	out := claimsToIntrospection(jwt.MapClaims{
		"sub":        uuid.NewString(),
		"session_id": sid.String(),
	})
	if out.SessionID != sid {
		t.Errorf("SessionID = %v, want %v — the CONF-10 liveness gate keys on this; unmapped means every token is treated as M2M and the gate never fires", out.SessionID, sid)
	}
}

// TestClaimsToIntrospection_NoSessionIDStaysZero pins the other half: a token
// that genuinely carries no session_id (M2M) maps to the zero UUID, which is
// what the gate reads as "exempt". Absent and unparseable must both be zero,
// never a partially-populated value.
func TestClaimsToIntrospection_NoSessionIDStaysZero(t *testing.T) {
	for name, claims := range map[string]jwt.MapClaims{
		"absent":       {"sub": uuid.NewString()},
		"empty_string": {"sub": uuid.NewString(), "session_id": ""},
		"unparseable":  {"sub": uuid.NewString(), "session_id": "not-a-uuid"},
		"wrong_type":   {"sub": uuid.NewString(), "session_id": 12345},
	} {
		t.Run(name, func(t *testing.T) {
			if out := claimsToIntrospection(claims); out.SessionID != uuid.Nil {
				t.Errorf("SessionID = %v, want uuid.Nil (M2M exemption reads zero as 'no session')", out.SessionID)
			}
		})
	}
}
