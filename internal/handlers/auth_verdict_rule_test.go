package handlers

// auth_verdict_rule_test.go — THE-SESSION-REJECTION-ROOT-CAUSE (2026-09-02).
//
// Ledger rule AUTH-VERDICT-HONEST-1 (the `RULE:` tag sits directly above the
// test function below, where rulefloor reads it).
//
// On the authentication path a store / infrastructure error NEVER answers
// 401 (it answers 503 with `reason: auth_store_error`, a correlation id in
// the body and the X-Request-ID header, and exactly one ERROR-log sink call
// carrying that same correlation id); a genuine verdict NEVER answers 503
// (it answers 401 with a non-empty `reason` and no log sink call). Pinned
// on the three doors that bit or could bite: the global bearer middleware
// (verifier key store, revocation store, liveness store), GET /api/v1/validate
// (session store, user store, verifier key store) and RFC 7662 introspection
// (verifier key store, revocation store), plus the correlation-id
// middleware that makes the log line joinable.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ── fakes ───────────────────────────────────────────────────────────────

type verdictVerifier struct {
	principal *domain.Principal
	err       error
}

func (f verdictVerifier) VerifyBearerToken(context.Context, string) (*domain.Principal, error) {
	return f.principal, f.err
}

type verdictRevocations struct {
	revoked bool
	err     error
}

func (f verdictRevocations) IsRevoked(context.Context, string) (bool, error) { return f.revoked, f.err }

type verdictLiveness struct {
	info *domain.SessionValidationInfo
	err  error
}

func (f verdictLiveness) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return f.info, f.err
}

type verdictSessionLookup struct {
	s   *domain.Session
	err error
}

func (f verdictSessionLookup) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return f.s, f.err
}

type verdictUserLookup struct {
	u   *domain.User
	err error
}

func (f verdictUserLookup) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return f.u, f.err
}

type verdictClaimsVerifier struct {
	claims *service.IntrospectionClaims
	err    error
}

func (f verdictClaimsVerifier) IntrospectToken(context.Context, string) (*service.IntrospectionClaims, error) {
	return f.claims, f.err
}

// sinkRecorder captures every AUTH-503 log sink call for the duration of a
// test and restores the production sink afterwards.
type sinkCall struct {
	where, cid string
	err        error
}

func recordAuthStoreSink(t *testing.T) *[]sinkCall {
	t.Helper()
	calls := &[]sinkCall{}
	prev := mw.AuthStoreErrorSink
	mw.AuthStoreErrorSink = func(_ context.Context, where, cid string, err error) {
		*calls = append(*calls, sinkCall{where: where, cid: cid, err: err})
	}
	t.Cleanup(func() { mw.AuthStoreErrorSink = prev })
	return calls
}

type verdictResponse struct {
	code   int
	header http.Header
	body   map[string]any
}

func doVerdict(r *gin.Engine, method, path string, headers map[string]string, form string) verdictResponse {
	var req *http.Request
	if form != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	body := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return verdictResponse{code: w.Code, header: w.Header(), body: body}
}

// assertStoreError503 is the 503 contract: status, body class, correlation
// id on body AND header, exactly one sink call with the same id and the
// expected `where`, and the sink's error carrying the driver detail.
func assertStoreError503(t *testing.T, label string, res verdictResponse, calls []sinkCall, cid, where string) {
	t.Helper()
	if res.code != http.StatusServiceUnavailable {
		t.Fatalf("%s: status = %d, want 503 (a store error is NOT a verdict)", label, res.code)
	}
	if res.body["error"] != "temporarily_unavailable" || res.body["reason"] != "auth_store_error" {
		t.Errorf("%s: body = %v, want error=temporarily_unavailable reason=auth_store_error", label, res.body)
	}
	if res.body["correlation_id"] != cid {
		t.Errorf("%s: body correlation_id = %v, want %q", label, res.body["correlation_id"], cid)
	}
	if got := res.header.Get(mw.CorrelationIDHeader); got != cid {
		t.Errorf("%s: %s header = %q, want %q", label, mw.CorrelationIDHeader, got, cid)
	}
	if res.header.Get("Retry-After") == "" {
		t.Errorf("%s: Retry-After header missing on a 503", label)
	}
	if len(calls) != 1 {
		t.Fatalf("%s: log sink calls = %d, want exactly 1 (every 503 has its log line)", label, len(calls))
	}
	if calls[0].cid != cid || calls[0].where != where || calls[0].err == nil {
		t.Errorf("%s: sink call = %+v, want cid=%q where=%q err!=nil", label, calls[0], cid, where)
	}
}

// assertVerdict401 is the 401 contract: status, error=unauthorized, a
// non-empty reason (equal to want when given), and NO sink call.
func assertVerdict401(t *testing.T, label string, res verdictResponse, calls []sinkCall, wantReason string) {
	t.Helper()
	if res.code != http.StatusUnauthorized {
		t.Fatalf("%s: status = %d, want 401 (a verdict is NOT a store error)", label, res.code)
	}
	reason, _ := res.body["reason"].(string)
	if reason == "" {
		t.Errorf("%s: 401 body %v carries no reason", label, res.body)
	}
	if wantReason != "" && reason != wantReason {
		t.Errorf("%s: reason = %q, want %q", label, reason, wantReason)
	}
	if len(calls) != 0 {
		t.Errorf("%s: a verdict must not log as a store error, sink calls = %d", label, len(calls))
	}
}

// ── the rule ────────────────────────────────────────────────────────────

// RULE: AUTH-VERDICT-HONEST-1
func TestRuleAuthVerdictHonest1_StoreErrorNever401_VerdictNever503_Every503Logged(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	uid, sid := uuid.New(), uuid.New()
	live := &domain.Session{ID: sid, UserID: uid, IsValid: true, ExpiresAt: time.Now().Add(time.Hour)}
	liveUser := &domain.User{ID: uid, Email: "u@example.test", Role: domain.RoleOrgUser}
	sessionPrincipal := &domain.Principal{UserID: uid, SessionID: sid, Sub: uid.String(), TokenID: "jti-1", Role: domain.RoleOrgUser}
	liveInfo := &domain.SessionValidationInfo{Session: live, UserActive: true, OrgActive: true}
	storeDown := errors.New("pgx: connection reset by peer")

	// ── door 1: the global bearer middleware ────────────────────────────
	bearerEngine := func(v mw.TokenVerifier, sessions mw.SessionRevocationLookup, revs mw.BearerRevocationLookup) *gin.Engine {
		r := gin.New()
		r.Use(mw.BearerPrincipal(nil, v, sessions, revs))
		r.Use(mw.RequireAuthenticated())
		r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
		return r
	}
	bearer := map[string]string{"Authorization": "Bearer tok", mw.CorrelationIDHeader: "cid-bearer"}

	t.Run("bearer control: live everything → 200", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: liveInfo}, verdictRevocations{}), http.MethodGet, "/probe", bearer, "")
		if res.code != http.StatusOK || len(*calls) != 0 {
			t.Fatalf("PREMISE: live token must pass: status=%d sink=%d", res.code, len(*calls))
		}
	})
	t.Run("bearer store: verifier key store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(bearerEngine(verdictVerifier{err: domain.AuthStoreUnavailable("signing-keys", storeDown)}, verdictLiveness{info: liveInfo}, verdictRevocations{}), http.MethodGet, "/probe", bearer, "")
		assertStoreError503(t, "bearer verifier store", res, *calls, "cid-bearer", "bearer.verify")
	})
	t.Run("bearer store: revocation store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: liveInfo}, verdictRevocations{err: storeDown}), http.MethodGet, "/probe", bearer, "")
		assertStoreError503(t, "bearer revocation store", res, *calls, "cid-bearer", "bearer.revocation")
	})
	t.Run("bearer store: liveness store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{err: storeDown}, verdictRevocations{}), http.MethodGet, "/probe", bearer, "")
		assertStoreError503(t, "bearer liveness store", res, *calls, "cid-bearer", "bearer.liveness")
	})
	t.Run("bearer verdicts: never 503, always a reason, never logged", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		assertVerdict401(t, "invalid token",
			doVerdict(bearerEngine(verdictVerifier{err: errors.New("signature invalid")}, verdictLiveness{info: liveInfo}, verdictRevocations{}), http.MethodGet, "/probe", bearer, ""),
			*calls, mw.ReasonTokenInvalid)
		assertVerdict401(t, "revoked jti",
			doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: liveInfo}, verdictRevocations{revoked: true}), http.MethodGet, "/probe", bearer, ""),
			*calls, mw.ReasonTokenRevoked)
		assertVerdict401(t, "session not live (no row)",
			doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: nil}, verdictRevocations{}), http.MethodGet, "/probe", bearer, ""),
			*calls, mw.ReasonSessionNotLive)
		assertVerdict401(t, "empty bearer",
			doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: liveInfo}, verdictRevocations{}), http.MethodGet, "/probe", map[string]string{"Authorization": "Bearer "}, ""),
			*calls, mw.ReasonMissingCredential)
		assertVerdict401(t, "no credential (guard)",
			doVerdict(bearerEngine(verdictVerifier{principal: sessionPrincipal}, verdictLiveness{info: liveInfo}, verdictRevocations{}), http.MethodGet, "/probe", nil, ""),
			*calls, mw.ReasonNoCredential)
	})

	// ── door 2: GET /api/v1/validate (the door that bit) ────────────────
	validateEngine := func(v mw.TokenVerifier, s verdictSessionLookup, u verdictUserLookup) *gin.Engine {
		r := gin.New()
		RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{TokenVerifier: v, SessionLookup: s, UserLookup: u})
		return r
	}
	validateHeaders := map[string]string{"Authorization": "Bearer tok", mw.CorrelationIDHeader: "cid-validate"}
	validatePrincipal := &domain.Principal{UserID: uid, SessionID: sid}

	t.Run("validate control → 200", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{s: live}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, "")
		if res.code != http.StatusOK || len(*calls) != 0 {
			t.Fatalf("PREMISE: live session must validate: status=%d sink=%d", res.code, len(*calls))
		}
	})
	t.Run("validate store: session store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{err: storeDown}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, "")
		assertStoreError503(t, "validate session store", res, *calls, "cid-validate", "validate.session")
	})
	t.Run("validate store: user store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{s: live}, verdictUserLookup{err: storeDown}), http.MethodGet, "/api/v1/validate", validateHeaders, "")
		assertStoreError503(t, "validate user store", res, *calls, "cid-validate", "validate.user")
	})
	t.Run("validate store: verifier key store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(validateEngine(verdictVerifier{err: domain.AuthStoreUnavailable("signing-keys", storeDown)}, verdictSessionLookup{s: live}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, "")
		assertStoreError503(t, "validate verifier store", res, *calls, "cid-validate", "validate.verify")
	})
	t.Run("validate verdicts: never 503, always a reason, never logged", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		assertVerdict401(t, "session not found",
			doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{err: domain.ErrSessionNotFound}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, ""),
			*calls, "session_not_found")
		assertVerdict401(t, "user not found",
			doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{s: live}, verdictUserLookup{err: domain.ErrUserNotFound}), http.MethodGet, "/api/v1/validate", validateHeaders, ""),
			*calls, "user_not_found")
		assertVerdict401(t, "invalid token",
			doVerdict(validateEngine(verdictVerifier{err: errors.New("bad signature")}, verdictSessionLookup{s: live}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, ""),
			*calls, mw.ReasonTokenInvalid)
		revoked := &domain.Session{ID: sid, UserID: uid, IsValid: false, ExpiresAt: time.Now().Add(time.Hour)}
		assertVerdict401(t, "session not usable",
			doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{s: revoked}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", validateHeaders, ""),
			*calls, "session_not_usable")
		assertVerdict401(t, "no credential",
			doVerdict(validateEngine(verdictVerifier{principal: validatePrincipal}, verdictSessionLookup{s: live}, verdictUserLookup{u: liveUser}), http.MethodGet, "/api/v1/validate", nil, ""),
			*calls, mw.ReasonMissingCredential)
	})

	// ── door 3: RFC 7662 introspection ──────────────────────────────────
	siteAdmin := &domain.Principal{Role: domain.RoleSiteAdmin, UserID: uuid.New()}
	introspectEngine := func(v service.TokenClaimsVerifier, revs service.TokenRevocationChecker) *gin.Engine {
		r := gin.New()
		r.Use(mw.InjectPrincipalForTest(siteAdmin))
		svc := service.NewIntrospectionService(nil, v, nil)
		if revs != nil {
			svc = svc.WithRevocationChecker(revs)
		}
		RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{IntrospectionService: svc, Audit: &audit.Recorder{}})
		return r
	}
	introHeaders := map[string]string{mw.CorrelationIDHeader: "cid-intro"}
	activeClaims := &service.IntrospectionClaims{Sub: uid.String(), Jti: "jti-1"}

	t.Run("introspection store: key store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(introspectEngine(verdictClaimsVerifier{err: domain.AuthStoreUnavailable("signing-keys", storeDown)}, nil), http.MethodPost, "/api/v1/oauth/introspection", introHeaders, "token=tok")
		assertStoreError503(t, "introspection key store", res, *calls, "cid-intro", "introspection")
	})
	t.Run("introspection store: revocation store down → 503", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		res := doVerdict(introspectEngine(verdictClaimsVerifier{claims: activeClaims}, verdictRevocations{err: storeDown}), http.MethodPost, "/api/v1/oauth/introspection", introHeaders, "token=tok")
		assertStoreError503(t, "introspection revocation store", res, *calls, "cid-intro", "introspection")
	})
	t.Run("introspection verdicts: 200 active:false, never 503, never logged", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		for label, eng := range map[string]*gin.Engine{
			"invalid token": introspectEngine(verdictClaimsVerifier{err: errors.New("bad signature")}, nil),
			"revoked jti":   introspectEngine(verdictClaimsVerifier{claims: activeClaims}, verdictRevocations{revoked: true}),
		} {
			res := doVerdict(eng, http.MethodPost, "/api/v1/oauth/introspection", introHeaders, "token=tok")
			if res.code != http.StatusOK || res.body["active"] != false {
				t.Errorf("%s: status=%d body=%v, want 200 active:false (RFC 7662 verdict)", label, res.code, res.body)
			}
		}
		if len(*calls) != 0 {
			t.Errorf("introspection verdicts must not log as store errors, sink calls = %d", len(*calls))
		}
	})

	// ── the correlation id itself ───────────────────────────────────────
	t.Run("correlation id: well-formed header echoed, garbage replaced by a uuid", func(t *testing.T) {
		r := gin.New()
		r.Use(mw.CorrelationIDMiddleware())
		r.GET("/cid", func(c *gin.Context) { c.String(http.StatusOK, mw.CorrelationID(c)) })
		good := doVerdict(r, http.MethodGet, "/cid", map[string]string{mw.CorrelationIDHeader: "req-abc_123.x"}, "")
		if good.header.Get(mw.CorrelationIDHeader) != "req-abc_123.x" {
			t.Errorf("well-formed id not echoed: %q", good.header.Get(mw.CorrelationIDHeader))
		}
		bad := doVerdict(r, http.MethodGet, "/cid", map[string]string{mw.CorrelationIDHeader: "bad id! <script>"}, "")
		echoed := bad.header.Get(mw.CorrelationIDHeader)
		if _, err := uuid.Parse(echoed); err != nil {
			t.Errorf("garbage id must be replaced by a uuid, got %q", echoed)
		}
	})
}
