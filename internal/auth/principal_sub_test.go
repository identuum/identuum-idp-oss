package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CONF-11 teeth, on the REAL producer. claimsToPrincipal is the only non-test
// producer of a *domain.Principal that reaches the bearer path, so this is
// where "Sub is the sub claim, verbatim" either holds or does not.
//
// The contract being served is pkg/oidc/subject.go:31 — "Subject is the token's
// `sub` claim, verbatim." internal/mw/bearer.go used to satisfy it with
// principal.UserID.String(), which is a DIFFERENT value in exactly the two
// cases below. Capturing Sub is what makes the correct value available at all.

// TestClaimsToPrincipal_NonUUIDSubIsCapturedVerbatim pins the case that used to
// lose the subject completely: a `sub` that is not a uuid. The uuid parse fails,
// UserID stays uuid.Nil, and BEFORE this change there was nowhere else the
// string survived — so a subject-keyed resolver would have been handed
// uuid.Nil's string, a well-formed key belonging to nobody.
func TestClaimsToPrincipal_NonUUIDSubIsCapturedVerbatim(t *testing.T) {
	const sub = "auth0|abc123" // a perfectly legal sub; not a uuid
	p, err := claimsToPrincipal(jwt.MapClaims{"sub": sub})
	if err != nil {
		t.Fatalf("claimsToPrincipal: %v", err)
	}
	if p.Sub != sub {
		t.Errorf("Sub = %q, want %q verbatim — a non-uuid sub must survive the uuid parse, or a subject-keyed resolver is asked about the wrong principal (CONF-11)", p.Sub, sub)
	}
	if p.UserID != uuid.Nil {
		t.Errorf("UserID = %v, want uuid.Nil — a non-uuid sub must not become a UserID", p.UserID)
	}
}

// TestClaimsToPrincipal_UserIDDoesNotOverwriteSub pins the more dangerous case.
// The `user_id` extension claim deliberately overwrites UserID, so UserID and
// `sub` can name different things. If user_id also clobbered Sub, the bearer
// door would ask a subject-keyed resolver about the user_id while userinfo asked
// about the sub — two doors, two principals, one token.
func TestClaimsToPrincipal_UserIDDoesNotOverwriteSub(t *testing.T) {
	sub := uuid.NewString()
	otherID := uuid.New() // a DIFFERENT principal than sub names
	if otherID.String() == sub {
		t.Fatal("fixture collision: user_id must differ from sub for this pin to mean anything")
	}

	p, err := claimsToPrincipal(jwt.MapClaims{"sub": sub, "user_id": otherID.String()})
	if err != nil {
		t.Fatalf("claimsToPrincipal: %v", err)
	}
	if p.Sub != sub {
		t.Errorf("Sub = %q, want the sub claim %q — user_id must NOT overwrite Sub; the two doors would resolve different principals (CONF-11)", p.Sub, sub)
	}
	if p.UserID != otherID {
		t.Errorf("UserID = %v, want the user_id claim %v (this overwrite is intended and must be preserved)", p.UserID, otherID)
	}
}

// TestClaimsToPrincipal_ParseableButNonCanonicalSubIsNotNormalised pins the
// third input class, and the one review proved was uncovered: a sub that IS a
// uuid but is not in canonical form.
//
// google/uuid.Parse accepts all four spellings below and uuid.UUID.String()
// re-serialises every one of them as lowercase-hyphenated — so `p.Sub = sub`
// and `p.Sub = id.String()` differ ONLY for these inputs. With the earlier
// tests covering just a canonical uuid and a non-uuid, a "normalise while I'm
// here" edit inside the uuid-parse branch (p.Sub = id.String()) silently
// lowercased the subject and left the ENTIRE repo suite green. "Verbatim"
// (pkg/oidc/subject.go:31) means byte-for-byte, and a subject-keyed store
// lookup is not obliged to be case-insensitive, so a normalised subject can
// simply miss.
func TestClaimsToPrincipal_ParseableButNonCanonicalSubIsNotNormalised(t *testing.T) {
	for _, sub := range []string{
		"550E8400-E29B-41D4-A716-446655440000",          // uppercase hex
		"urn:uuid:550e8400-e29b-41d4-a716-446655440000", // RFC 4122 URN form
		"{550e8400-e29b-41d4-a716-446655440000}",        // braced
		"550e8400e29b41d4a716446655440000",              // unhyphenated
	} {
		t.Run(sub, func(t *testing.T) {
			// Guard the premise: if Parse ever stops accepting this form the
			// case is vacuous, and a silently vacuous test is worse than none.
			if _, err := uuid.Parse(sub); err != nil {
				t.Fatalf("premise broken: uuid.Parse(%q) now errors (%v), so this case no longer exercises the parse branch", sub, err)
			}
			p, err := claimsToPrincipal(jwt.MapClaims{"sub": sub})
			if err != nil {
				t.Fatalf("claimsToPrincipal: %v", err)
			}
			if p.Sub != sub {
				t.Errorf("Sub = %q, want %q byte-for-byte — a parseable sub must NOT be normalised through uuid.String(); verbatim means verbatim, and a subject-keyed lookup can miss on a re-spelled key (CONF-11)", p.Sub, sub)
			}
		})
	}
}

// TestClaimsToPrincipal_AbsentSubStaysEmpty pins the zero value. `sub` is NOT
// required on this path (VerifyBearerToken passes
// jwtpolicy.Required{Expiration: true} only, so monolith tokens may carry
// user_id instead), which is precisely why bearer.go must not invent a subject:
// empty means "this token names no subject", and a subject-keyed resolver has
// to be allowed to deny on it rather than be handed a uuid-shaped guess.
func TestClaimsToPrincipal_AbsentSubStaysEmpty(t *testing.T) {
	for name, claims := range map[string]jwt.MapClaims{
		"absent":       {"user_id": uuid.NewString()},
		"empty_string": {"sub": "", "user_id": uuid.NewString()},
		"wrong_type":   {"sub": 12345, "user_id": uuid.NewString()},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := claimsToPrincipal(claims)
			if err != nil {
				t.Fatalf("claimsToPrincipal: %v", err)
			}
			if p.Sub != "" {
				t.Errorf("Sub = %q, want empty — no sub claim means no subject, not a substituted one", p.Sub)
			}
			if p.UserID == uuid.Nil {
				t.Errorf("UserID = uuid.Nil, want the user_id claim — the monolith fallback must still work")
			}
		})
	}
}
