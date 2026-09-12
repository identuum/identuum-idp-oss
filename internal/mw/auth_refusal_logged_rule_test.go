package mw

// THE-SILENT-REFUSAL / AUTH-REFUSAL-LOGGED-1. Every 401 written by
// RespondUnauthenticatedReason — the bearer populator's four verdicts and the
// guard's no-credential verdict — must leave ONE security log line naming the
// reason code, and that line must carry NO credential material: not the
// token, not the Authorization header, not the scheme. Both halves are
// measured here against the REAL logger seam (logger.Security swapped for a
// zap observer for the test's duration), the same seam the runtime tests use.
// The response itself — status and body — must be byte-for-byte what it was
// before the line was logged: this is a diagnostic, not a verdict change.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
)

// refusalToken is deliberately distinctive so a search of the log output for
// it is a real negative proof, not a coincidence of short strings.
const refusalToken = "eyJ-REFUSAL-TOKEN-MUST-NEVER-REACH-A-LOG-LINE-9f3c1d"

type refusalVerifier struct {
	principal *domain.Principal
	err       error
}

func (v refusalVerifier) VerifyBearerToken(context.Context, string) (*domain.Principal, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.principal, nil
}

type refusalSessions struct{ info *domain.SessionValidationInfo }

func (s refusalSessions) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return s.info, nil
}

type refusalRevocations struct{ revoked bool }

func (r refusalRevocations) IsRevoked(context.Context, string) (bool, error) { return r.revoked, nil }

// observeSecurityLog swaps the package security logger for an observer and
// restores it when the test ends — the seam internal/runtime's logging tests
// use, so what is observed here is what the appliance would have written.
func observeSecurityLog(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	orig := logger.Security
	core, observed := observer.New(zapcore.InfoLevel)
	logger.Security = logger.NewLogger(zap.New(core), zapcore.InfoLevel)
	t.Cleanup(func() { logger.Security = orig })
	return observed
}

func refusalEngine(v TokenVerifier, sessions SessionRevocationLookup, revs BearerRevocationLookup) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, v, sessions, revs))
	r.Use(RequireAuthenticated())
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doRefusal(engine *gin.Engine, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.RemoteAddr = "203.0.113.9:44444"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// renderEntry flattens a log entry — message plus every field's value — into
// one string so the negative proof can search ALL of it.
func renderEntry(e observer.LoggedEntry) string {
	var b strings.Builder
	b.WriteString(e.Message)
	for k, v := range e.ContextMap() {
		fmt.Fprintf(&b, " %s=%v", k, v)
	}
	return b.String()
}

// RULE: AUTH-REFUSAL-LOGGED-1
func TestRuleAuthRefusalLogged1_EveryReasonLogged_NoCredentialInTheLine_BodyUnchanged(t *testing.T) {
	uid, sid := uuid.New(), uuid.New()
	sessionPrincipal := &domain.Principal{UserID: uid, SessionID: sid, Sub: uid.String(), TokenID: "jti-1", Role: domain.RoleOrgUser}
	liveInfo := &domain.SessionValidationInfo{
		Session:    &domain.Session{ID: sid, UserID: uid, IsValid: true, ExpiresAt: time.Now().Add(time.Hour)},
		UserActive: true,
		OrgActive:  true,
	}
	bearer := "Bearer " + refusalToken

	cases := []struct {
		name       string
		engine     *gin.Engine
		authHeader string
		wantReason string
	}{
		{"no credential (guard)", refusalEngine(refusalVerifier{principal: sessionPrincipal}, refusalSessions{info: liveInfo}, refusalRevocations{}), "", ReasonNoCredential},
		{"empty bearer", refusalEngine(refusalVerifier{principal: sessionPrincipal}, refusalSessions{info: liveInfo}, refusalRevocations{}), "Bearer ", ReasonMissingCredential},
		{"verifier rejects", refusalEngine(refusalVerifier{err: errors.New("stub: signature")}, refusalSessions{info: liveInfo}, refusalRevocations{}), bearer, ReasonTokenInvalid},
		{"jti revoked", refusalEngine(refusalVerifier{principal: sessionPrincipal}, refusalSessions{info: liveInfo}, refusalRevocations{revoked: true}), bearer, ReasonTokenRevoked},
		{"session not live", refusalEngine(refusalVerifier{principal: sessionPrincipal}, refusalSessions{info: nil}, refusalRevocations{}), bearer, ReasonSessionNotLive},
	}

	// PREMISE (non-emptiness): a live everything passes and logs NO refusal,
	// so the counts below cannot be satisfied by a logger that fires always.
	t.Run("control: live token → 200 and no refusal line", func(t *testing.T) {
		observed := observeSecurityLog(t)
		w := doRefusal(refusalEngine(refusalVerifier{principal: sessionPrincipal}, refusalSessions{info: liveInfo}, refusalRevocations{}), bearer)
		if w.Code != http.StatusOK {
			t.Fatalf("PREMISE: live token must pass, got %d body=%s", w.Code, w.Body.String())
		}
		if n := observed.FilterMessage("authentication refused").Len(); n != 0 {
			t.Fatalf("PREMISE: a passing request logged %d refusal line(s), want 0", n)
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observed := observeSecurityLog(t)
			w := doRefusal(tc.engine, tc.authHeader)

			// (a) The verdict is unchanged: 401 with exactly the body it had.
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (the refusal itself must not change)", w.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not the JSON verdict: %v (%s)", err, w.Body.String())
			}
			if body["error"] != "unauthorized" || body["reason"] != tc.wantReason || len(body) != 2 {
				t.Fatalf("body = %s, want {error:unauthorized, reason:%s} and nothing else", w.Body.String(), tc.wantReason)
			}

			// (b) Exactly one security line names the reason code.
			lines := observed.FilterMessage("authentication refused").All()
			if len(lines) != 1 {
				t.Fatalf("refusal lines = %d, want exactly 1 — the 401 is silent again (reason %s)", len(lines), tc.wantReason)
			}
			fields := lines[0].ContextMap()
			if fields["reason"] != tc.wantReason {
				t.Fatalf("logged reason = %v, want %s", fields["reason"], tc.wantReason)
			}
			if fields["event_type"] != "auth_refused" || fields["method"] != http.MethodGet || fields["path"] != "/probe" || fields["ip_address"] != "203.0.113.9" {
				t.Fatalf("log fields = %v, want event_type=auth_refused method=GET path=/probe ip_address=203.0.113.9", fields)
			}
			if lines[0].Level != zapcore.WarnLevel {
				t.Fatalf("level = %s, want WARN", lines[0].Level)
			}

			// (c) NEGATIVE PROOF: no credential material anywhere in ANY line
			// the request produced — not the token, not the header, not the
			// scheme. Searched over the message and every field value.
			for _, e := range observed.All() {
				rendered := renderEntry(e)
				for _, forbidden := range []string{refusalToken, "Authorization", "Bearer"} {
					if strings.Contains(rendered, forbidden) {
						t.Fatalf("credential material in a log line: %q found in %q", forbidden, rendered)
					}
				}
			}
		})
	}
}
