package mw

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// CONF-11 teeth on the HEADER path: what BearerPrincipal puts in
// oidc.PrincipalRef.Subject must be the `sub` claim VERBATIM, per that field's
// contract (pkg/oidc/subject.go:31).
//
// It was principal.UserID.String(). That is a different value whenever the
// token's sub is not a uuid (UserID is then uuid.Nil) or a `user_id` claim is
// present (it overwrites UserID). CE's resolver keys on Subject and ignores
// SessionID (identuum-idp-ce token_liveness.go: resolveLiveUser(ref.Subject) ->
// users.GetBySubject), and internal/handlers/userinfo.go passes claims.Sub —
// correctly. So with a subject-keyed resolver wired, the two doors asked about
// DIFFERENT principals for the same token.
//
// Nothing breaks in OSS today because OSS's own resolver is session-keyed and
// never reads Subject (sessionSubjectResolver.ResolveSubject). These pins exist
// so the contract is enforced BEFORE a subject-keyed resolver is wired, not
// after it misbehaves. stubSubjectResolver.lastRef is the capture.

// subjectPrincipal builds a session-carrying principal whose Sub and UserID are
// deliberately DIFFERENT, which is the only configuration that can tell the two
// implementations apart.
func subjectPrincipal(sub string, userID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		Sub:       sub,
		UserID:    userID,
		Role:      domain.RoleSiteAdmin,
		SessionID: uuid.New(),
	}
}

// TestBearerPrincipal_RefSubjectIsNonUUIDSubVerbatim covers a sub that is not a
// uuid. Before the change UserID was uuid.Nil here, so the resolver was handed
// "00000000-0000-0000-0000-000000000000" — a well-formed lookup key that names
// nobody.
func TestBearerPrincipal_RefSubjectIsNonUUIDSubVerbatim(t *testing.T) {
	const sub = "auth0|abc123"
	principal := subjectPrincipal(sub, uuid.Nil)

	v := &stubVerifier{want: "t", principal: principal}
	captured := &stubSubjectResolver{ok: true}

	r := resolverEngine(v, &stubSessionLookup{session: usableSession()}, WithSubjectResolver(captured))
	if code := doProbe(r); code != http.StatusOK {
		t.Fatalf("probe status = %d, want 200 — this pin is about the ref, so the request must reach the route", code)
	}
	if captured.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 — nothing was captured, so the assertion below would be vacuous", captured.calls)
	}
	if captured.lastRef.Subject != sub {
		t.Errorf("PrincipalRef.Subject = %q, want the sub claim %q verbatim — a subject-keyed resolver is being asked about the wrong principal, while userinfo asks about the real sub (CONF-11)", captured.lastRef.Subject, sub)
	}
}

// TestBearerPrincipal_RefSubjectIsSubNotUserID covers the divergence that is
// dangerous rather than merely wrong: a `user_id` claim made UserID name a
// DIFFERENT principal than sub. Sending that uuid to a subject-keyed store can
// resolve some other principal's liveness and return a confidently wrong
// verdict, in either direction.
func TestBearerPrincipal_RefSubjectIsSubNotUserID(t *testing.T) {
	sub := uuid.NewString()
	otherID := uuid.New()
	if otherID.String() == sub {
		t.Fatal("fixture collision: UserID must differ from Sub for this pin to mean anything")
	}
	principal := subjectPrincipal(sub, otherID)

	v := &stubVerifier{want: "t", principal: principal}
	captured := &stubSubjectResolver{ok: true}

	r := resolverEngine(v, &stubSessionLookup{session: usableSession()}, WithSubjectResolver(captured))
	if code := doProbe(r); code != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", code)
	}
	if captured.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", captured.calls)
	}
	if got := captured.lastRef.Subject; got != sub {
		t.Errorf("PrincipalRef.Subject = %q, want the sub claim %q — got the UserID instead, so this door resolves a DIFFERENT principal than userinfo does for the same token (CONF-11)", got, sub)
	}
	// The session half of the ref must be untouched by this change.
	if captured.lastRef.SessionID != principal.SessionID.String() {
		t.Errorf("PrincipalRef.SessionID = %q, want %q — the session-keyed half of the ref must be unchanged", captured.lastRef.SessionID, principal.SessionID.String())
	}
}

// TestBearerPrincipal_EmptySubIsNotSubstituted pins the deliberate absence of a
// fallback. `sub` is not required on this path (VerifyBearerToken passes
// jwtpolicy.Required{Expiration: true}), so a session-carrying token with only
// user_id is reachable. The resolver must receive "" and be free to deny, NOT a
// uuid-shaped guess that could collide with a real subject.
func TestBearerPrincipal_EmptySubIsNotSubstituted(t *testing.T) {
	principal := subjectPrincipal("", uuid.New()) // no sub, real UserID

	v := &stubVerifier{want: "t", principal: principal}
	captured := &stubSubjectResolver{ok: true}

	r := resolverEngine(v, &stubSessionLookup{session: usableSession()}, WithSubjectResolver(captured))
	if code := doProbe(r); code != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", code)
	}
	if captured.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", captured.calls)
	}
	if captured.lastRef.Subject != "" {
		t.Errorf("PrincipalRef.Subject = %q, want \"\" — an absent sub must NOT be substituted with the UserID; a guess that collides with another principal's subject resolves the wrong liveness, which is worse than a refusal (CONF-11)", captured.lastRef.Subject)
	}
}
