package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ── AYGHU-4 fixtures: introspection over tokens the token endpoint minted ──

// acJTIStore is both the revoker a revocation propagates into and the
// checker introspection consults — the same oauth_token_revocations table
// in production.
type acJTIStore struct {
	mu      sync.Mutex
	revoked map[string]time.Time
	fail    error
}

func (s *acJTIStore) RevokeJTI(_ context.Context, jti string, expiresAt time.Time, _ string, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if s.revoked == nil {
		s.revoked = map[string]time.Time{}
	}
	s.revoked[jti] = expiresAt
	return nil
}

func (s *acJTIStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return false, s.fail
	}
	_, ok := s.revoked[jti]
	return ok, nil
}

var errMintedTokenInvalid = errors.New("token invalid")

// minterBackedIntrospector plays the signature verifier for tokens the
// captureMinter issued: it hands back the SIGNED claim set (as the real
// verifier does) and refuses unknown or expired tokens.
type minterBackedIntrospector struct {
	minter *captureMinter
	now    func() time.Time
	fail   error
}

func (v *minterBackedIntrospector) IntrospectToken(_ context.Context, raw string) (*service.IntrospectionClaims, error) {
	if v.fail != nil {
		return nil, v.fail
	}
	c, ok := v.minter.claimsFor(raw)
	if !ok {
		return nil, errMintedTokenInvalid
	}
	now := time.Now()
	if v.now != nil {
		now = v.now()
	}
	if !c.ExpiresAt.After(now) {
		return nil, errMintedTokenInvalid
	}
	out := &service.IntrospectionClaims{
		Sub: c.Subject, ClientID: c.ClientID, Scope: c.Scope, Iss: c.Issuer, Aud: []string{c.Audience},
		Exp: c.ExpiresAt.Unix(), Iat: c.IssuedAt.Unix(), Jti: c.JTI, ActorType: c.ActorType, Extra: map[string]any{},
	}
	if org, ok := c.Extra["org_id"].(string); ok {
		out.OrgID, _ = uuid.Parse(org)
	}
	if nbf, ok := c.Extra["nbf"].(int64); ok {
		out.Nbf = nbf
	}
	for _, k := range []string{"cnf", "agent_communication", "authorization_details"} {
		if v, ok := c.Extra[k]; ok {
			out.Extra[k] = v
		}
	}
	// The real verifier hands back JSON-decoded maps; mirror that shape.
	if d, ok := out.Extra["authorization_details"]; ok {
		b, _ := json.Marshal(d)
		var generic any
		_ = json.Unmarshal(b, &generic)
		out.Extra["authorization_details"] = generic
	}
	return out, nil
}

// acIntrospectWorld extends the token world with propagation and an
// introspection endpoint over the same stores.
type acIntrospectWorld struct {
	*acTokenWorld
	jtis     *acJTIStore
	verifier *minterBackedIntrospector
	intro    *service.IntrospectionService
}

func newACIntrospectWorld(t *testing.T) *acIntrospectWorld {
	t.Helper()
	base := newACTokenWorld(t)
	w := &acIntrospectWorld{acTokenWorld: base, jtis: &acJTIStore{}}
	w.verifier = &minterBackedIntrospector{minter: w.minter}
	w.svc.WithRevocationPropagation(w.issued, w.jtis)
	report := lifecycle.NewStartupReport()
	w.intro = service.NewIntrospectionService(report, w.verifier, nil).
		WithRevocationChecker(w.jtis).
		WithAgentCommunication(w.repo, w.clients)
	require.False(t, report.HasFatal())
	return w
}

func (w *acIntrospectWorld) introspectEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.CorrelationIDMiddleware())
	r.POST("/api/v1/oauth/introspection", HandleIntrospection(IntrospectionHandlerDeps{IntrospectionService: w.intro, Audit: w.audit}))
	return r
}

func postIntrospect(t *testing.T, r *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// issueFor obtains a participant token for the given client/key/ACI through
// the token endpoint (200 required).
func (w *acIntrospectWorld) issueFor(t *testing.T, cl *domain.Client, key dpopKey, aci uuid.UUID) string {
	t.Helper()
	form := w.tokenForm()
	form.Set("authorization_details", acTokenDetails(w.auth.ID, aci))
	rec := postToken(t, w.engine(w.authClient(cl)), form, mintDPoP(t, key, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return tokenJSON(t, rec)["access_token"].(string)
}

func introspectJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())
	return m
}

// ── tests ─────────────────────────────────────────────────────────────────

func TestIntrospectAgentComm_TruthTableOnTheWire(t *testing.T) {
	w := newACIntrospectWorld(t)
	r := w.introspectEngine()
	tokenA := w.issueFor(t, w.clA1, w.keyA, w.aci(domain.AgentCommunicationRoleInitiator))

	t.Run("active participant token", func(t *testing.T) {
		rec := postIntrospect(t, r, tokenA)
		require.Equal(t, http.StatusOK, rec.Code)
		body := introspectJSON(t, rec)
		assert.Equal(t, true, body["active"])
		assert.Equal(t, "DPoP", body["token_type"])
		assert.Equal(t, w.saA1.ID.String(), body["sub"])
		assert.Equal(t, w.clA1.ClientID, body["client_id"])
		ac := body["agent_communication"].(map[string]any)
		assert.Equal(t, w.auth.ID.String(), ac["authorization_id"])
		assert.Equal(t, "initiator", ac["role"])
	})
	t.Run("malformed token → inactive", func(t *testing.T) {
		rec := postIntrospect(t, r, "not.a.token")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, map[string]any{"active": false}, introspectJSON(t, rec))
	})
	t.Run("expired token → inactive", func(t *testing.T) {
		w.verifier.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
		defer func() { w.verifier.now = nil }()
		rec := postIntrospect(t, r, tokenA)
		assert.Equal(t, map[string]any{"active": false}, introspectJSON(t, rec))
	})
	t.Run("jti revoked directly → inactive", func(t *testing.T) {
		tokenB := w.issueFor(t, w.clA2, w.keyB, w.aci(domain.AgentCommunicationRoleResponder))
		claims, _ := w.minter.claimsFor(tokenB)
		require.NoError(t, w.jtis.RevokeJTI(context.Background(), claims.JTI, claims.ExpiresAt, "manual", nil))
		rec := postIntrospect(t, r, tokenB)
		assert.Equal(t, map[string]any{"active": false}, introspectJSON(t, rec))
	})
	t.Run("participant binding no longer valid → inactive", func(t *testing.T) {
		other := uuid.New()
		w.clA1.ServiceAccountID = &other
		defer func() { w.clA1.ServiceAccountID = &w.saA1.ID }()
		rec := postIntrospect(t, r, tokenA)
		assert.Equal(t, map[string]any{"active": false}, introspectJSON(t, rec))
	})
	t.Run("empty token → invalid_request", func(t *testing.T) {
		rec := postIntrospect(t, r, "")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestIntrospectAgentComm_SigningKeyStoreErrorIs503(t *testing.T) {
	w := newACIntrospectWorld(t)
	tokenA := w.issueFor(t, w.clA1, w.keyA, w.aci(domain.AgentCommunicationRoleInitiator))
	w.verifier.fail = domain.AuthStoreUnavailable("signing-keys", fmt.Errorf("connection refused"))
	rec := postIntrospect(t, w.introspectEngine(), tokenA)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "auth_store_error", introspectJSON(t, rec)["reason"])
}
