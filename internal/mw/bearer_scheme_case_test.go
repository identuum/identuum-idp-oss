package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// CONF-8 teeth: the Authorization scheme is case-INSENSITIVE per RFC 6750
// §2.1, and BearerPrincipal must agree with the handlers that parse the
// header themselves.
//
// The defect: BearerPrincipal matched `"Bearer "` with strings.HasPrefix —
// case-SENSITIVELY — while three handlers use a case-insensitive match
// (internal/handlers/userinfo.go readUserinfoBearerToken, auth_sessions.go
// extractValidateToken, dcr.go extractBearerToken). So `bearer <token>` and
// `Bearer <token>` took DIFFERENT paths through one request: the capitalised
// form was populated and gated by this middleware — signature, jti
// revocation, and session/user/org liveness via the SubjectResolver — while
// the lowercase form fell through the prefix check unpopulated, and was then
// picked up by a handler whose own gate set is weaker.
//
// Concretely, the case that motivated this: a token belonging to a BANNED
// user. Presented as `Bearer` it is refused. Presented as `bearer` it was
// not, because the middleware never looked at it.
//
// Every stubVerifier below sets want:"t" — i.e. it accepts ONLY the bare
// token, the way a real JWT verifier does. Without that the stub accepts any
// string, and a middleware that forgot to strip a non-canonical scheme (the
// TrimPrefix bug review caught) would sail through green.
//
// doProbeScheme mirrors doProbe but lets the caller choose the scheme casing.
func doProbeScheme(r *http.Handler, scheme string) int {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", scheme+" t")
	rec := httptest.NewRecorder()
	(*r).ServeHTTP(rec, req)
	return rec.Code
}

// TestBearerPrincipal_LowercaseSchemeIsGatedLikeCapitalised is the CONF-8
// pin. A resolver that says "not live" (the banned-user verdict) must produce
// a 401 for BOTH casings. Before the fix the lowercase arm returned 200,
// because the middleware skipped the header entirely.
func TestBearerPrincipal_LowercaseSchemeIsGatedLikeCapitalised(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			v := &stubVerifier{want: "t", principal: sessionPrincipal()}
			sessions := &stubSessionLookup{session: usableSession()}
			// ok=false is the banned/deleted-user (or inactive-org) verdict.
			stub := &stubSubjectResolver{ok: false}

			var h http.Handler = resolverEngine(v, sessions, WithSubjectResolver(stub))
			if code := doProbeScheme(&h, scheme); code != http.StatusUnauthorized {
				t.Errorf("scheme %q with a not-live principal: status = %d, want 401 — RFC 6750 makes the scheme case-insensitive, so every casing must reach the same gates", scheme, code)
			}
			if stub.calls == 0 {
				t.Errorf("scheme %q: the subject resolver was never consulted — the middleware did not treat this as a Bearer presentation at all", scheme)
			}
		})
	}
}

// TestBearerPrincipal_LowercaseSchemeAdmitsWhenLive is the other half: making
// the match case-insensitive must not turn the lowercase form into a blanket
// reject either. A live principal is admitted under every casing.
func TestBearerPrincipal_LowercaseSchemeAdmitsWhenLive(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		t.Run(scheme, func(t *testing.T) {
			v := &stubVerifier{want: "t", principal: sessionPrincipal()}
			sessions := &stubSessionLookup{session: usableSession()}
			stub := &stubSubjectResolver{ok: true}

			var h http.Handler = resolverEngine(v, sessions, WithSubjectResolver(stub))
			if code := doProbeScheme(&h, scheme); code != http.StatusOK {
				t.Errorf("scheme %q with a live principal: status = %d, want 200", scheme, code)
			}
		})
	}
}

// TestBearerPrincipal_NonBearerSchemeStillPassesThrough pins that widening the
// match to any casing of "bearer" did NOT widen it to other schemes: Basic
// must still pass through unpopulated (CONF-1), not be parsed as a token.
func TestBearerPrincipal_NonBearerSchemeStillPassesThrough(t *testing.T) {
	v := &stubVerifier{want: "t", principal: sessionPrincipal()}
	sessions := &stubSessionLookup{session: usableSession()}
	stub := &stubSubjectResolver{ok: true}

	var h http.Handler = resolverEngine(v, sessions, WithSubjectResolver(stub))
	// Basic reaches the route (no principal planted, no guard on this probe).
	if code := doProbeScheme(&h, "Basic"); code != http.StatusOK {
		t.Errorf("Basic scheme: status = %d, want pass-through (CONF-1)", code)
	}
	if v.calls != 0 {
		t.Errorf("verifier called for a Basic scheme: calls = %d — the widening must cover casing only, not other schemes", v.calls)
	}
}
