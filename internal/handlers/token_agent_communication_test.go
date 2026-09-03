package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// ── AYGHU-3 fixtures: the token endpoint with the agent-communication path ──

const tokenEndpointURL = "https://idp.test/api/v1/oauth/token"

// captureMinter records the claims the token endpoint asked to sign and
// returns an opaque stand-in; the wire token's shape is the service tests'
// concern, the handler tests assert the CONTRACT (claims, token_type).
type captureMinter struct {
	mu    sync.Mutex
	calls int
	last  oidc.TokenClaims
	byJTI map[string]oidc.TokenClaims
}

func (m *captureMinter) Mint(_ context.Context, c oidc.TokenClaims) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.last = c
	if m.byJTI == nil {
		m.byJTI = map[string]oidc.TokenClaims{}
	}
	m.byJTI[c.JTI] = c
	return "test-token-" + c.JTI, c.JTI, nil
}

// claimsFor returns the claims minted under a wire token ("test-token-<jti>").
func (m *captureMinter) claimsFor(wireToken string) (oidc.TokenClaims, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byJTI[strings.TrimPrefix(wireToken, "test-token-")]
	return c, ok && strings.HasPrefix(wireToken, "test-token-")
}

type acReplayMarkerFake struct {
	mu   sync.Mutex
	seen map[string]bool
	fail error
}

func (f *acReplayMarkerFake) Mark(_ context.Context, jkt, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return false, f.fail
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	k := jkt + "|" + jti
	if f.seen[k] {
		return false, nil
	}
	f.seen[k] = true
	return true, nil
}

// acIssuedTokensStub is an in-memory AgentCommunicationTokenRepository.
type acIssuedTokensStub struct {
	mu   sync.Mutex
	rows []domain.AgentCommunicationToken
	fail error
}

func (f *acIssuedTokensStub) Insert(_ context.Context, t *domain.AgentCommunicationToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.rows = append(f.rows, *t)
	return nil
}

func (f *acIssuedTokensStub) ListActiveByAuthorization(_ context.Context, authID uuid.UUID, now time.Time) ([]domain.AgentCommunicationToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	var out []domain.AgentCommunicationToken
	for _, r := range f.rows {
		if r.AuthorizationID == authID && r.ExpiresAt.After(now) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *acIssuedTokensStub) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

type dpopKey struct {
	priv ed25519.PrivateKey
	jwk  map[string]any
	jkt  string
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	jkt, err := service.JWKThumbprint(jwk)
	require.NoError(t, err)
	return dpopKey{priv: priv, jwk: jwk, jkt: jkt}
}

func mintDPoP(t *testing.T, k dpopKey, jti string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"htm": "POST", "htu": tokenEndpointURL, "iat": time.Now().Unix(), "jti": jti,
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = k.jwk
	s, err := tok.SignedString(k.priv)
	require.NoError(t, err)
	return s
}

// acTokenWorld: an AYGHU-2 world (org, admin, two agents), one active
// authorization enrolled with two fresh proof keys, the token endpoint.
type acTokenWorld struct {
	*acTestWorld
	auth    *domain.AgentCommunicationAuthorization
	keyA    dpopKey
	keyB    dpopKey
	minter  *captureMinter
	replays *acReplayMarkerFake
	issued  *acIssuedTokensStub
	tokens  *service.TokenService
	audit   *audit.Recorder
}

func newACTokenWorld(t *testing.T) *acTokenWorld {
	t.Helper()
	base := newACWorld(t)
	w := &acTokenWorld{acTestWorld: base, keyA: newDPoPKey(t), keyB: newDPoPKey(t), minter: &captureMinter{}, replays: &acReplayMarkerFake{}, issued: &acIssuedTokensStub{}, audit: &audit.Recorder{}}
	// The token service runs on the wall clock (the handler has no clock
	// seam of its own), so the authorization must be live NOW.
	a, err := w.svc.CreateForActor(context.Background(), w.adminA, service.CreateAgentCommunicationAuthorizationInput{
		RelayAudience: "https://relay.example.test/session", ExpiresAt: time.Now().Add(time.Hour), MaxMessages: 10, MaxMessageSizeBytes: 4096,
		Participants: []service.AgentCommunicationParticipantInput{
			{ServiceAccountID: w.saA1.ID, ClientID: w.clA1.ClientID, Role: domain.AgentCommunicationRoleInitiator, ProofKeyThumbprint: w.keyA.jkt, Capabilities: []string{"repository.read"}},
			{ServiceAccountID: w.saA2.ID, ClientID: w.clA2.ClientID, Role: domain.AgentCommunicationRoleResponder, ProofKeyThumbprint: w.keyB.jkt},
		},
	})
	require.NoError(t, err)
	w.auth = a
	report := lifecycle.NewStartupReport()
	w.tokens = service.NewTokenService(report, &handlerKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test", Minter: w.minter}).
		WithAgentCommunication(service.AgentCommunicationIssuanceDeps{
			Authorizations: w.repo, ServiceAccounts: w.sas, Clients: w.clients, Replays: w.replays, IssuedTokens: w.issued, TokenEndpointURL: tokenEndpointURL,
		})
	require.False(t, report.HasFatal())
	return w
}

func (w *acTokenWorld) engine(client *service.AuthenticatedClient) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.CorrelationIDMiddleware())
	r.Use(func(c *gin.Context) {
		if client != nil {
			mw.SetAuthenticatedClientForTest(c, client)
		}
		c.Next()
	})
	r.POST("/api/v1/oauth/token", HandleToken(TokenHandlerDeps{TokenService: w.tokens, Audit: w.audit}))
	return r
}

func (w *acTokenWorld) authClient(cl *domain.Client) *service.AuthenticatedClient {
	return &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: cl.ClientID, AuthRecordID: cl.ID, OrganizationID: w.orgA}
}

func (w *acTokenWorld) aci(role domain.AgentCommunicationParticipantRole) uuid.UUID {
	return w.auth.Participant(role).ACI
}

func acTokenDetails(authID, aci uuid.UUID) string {
	return fmt.Sprintf(`[{"type":"agent_communication","authorization_id":%q,"aci":%q}]`, authID, aci)
}

// tokenForm is the default well-formed request for participant A.
func (w *acTokenWorld) tokenForm() url.Values {
	return url.Values{
		"grant_type":            {"client_credentials"},
		"audience":              {w.auth.RelayAudience},
		"authorization_details": {acTokenDetails(w.auth.ID, w.aci(domain.AgentCommunicationRoleInitiator))},
	}
}

func postToken(t *testing.T, r *gin.Engine, form url.Values, dpop string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func tokenJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())
	return m
}

func (w *acTokenWorld) refusals() []audit.Event {
	var out []audit.Event
	for _, ev := range w.audit.Events() {
		if ev.Action == AuditActionAgentCommunicationTokenRefused {
			out = append(out, ev)
		}
	}
	return out
}

// ── tests ─────────────────────────────────────────────────────────────────

func TestTokenAgentComm_HappyPath_ContractOnTheWire(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))
	proof := mintDPoP(t, w.keyA, uuid.NewString())
	rec := postToken(t, r, w.tokenForm(), proof)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := tokenJSON(t, rec)
	assert.Equal(t, "DPoP", body["token_type"])
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "agent_communication", body["scope"])
	assert.EqualValues(t, 300, body["expires_in"])
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh, "no refresh token")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	require.Equal(t, 1, w.minter.calls)
	claims := w.minter.last
	assert.Equal(t, w.saA1.ID.String(), claims.Subject)
	assert.Equal(t, w.auth.RelayAudience, claims.Audience)
	assert.Equal(t, w.clA1.ClientID, claims.ClientID)
	cnf := claims.Extra["cnf"].(map[string]any)
	assert.Equal(t, w.keyA.jkt, cnf["jkt"])
	ac := claims.Extra["agent_communication"].(map[string]any)
	assert.Equal(t, w.auth.ID.String(), ac["authorization_id"])
	assert.Equal(t, w.aci(domain.AgentCommunicationRoleInitiator).String(), ac["aci"])
	assert.Equal(t, w.auth.PolicyDigest, ac["policy_digest"])

	// Audit: the generic oauth_token.issued (token_type DPoP) plus the
	// agent-communication issued event, safe metadata only.
	var issued *audit.Event
	for _, ev := range w.audit.Events() {
		if ev.Action == AuditActionAgentCommunicationTokenIssued {
			e := ev
			issued = &e
		}
	}
	require.NotNil(t, issued)
	assert.Equal(t, "success", issued.Outcome)
	assert.Equal(t, w.auth.ID.String(), issued.Metadata["authorization_id"])
	assert.Equal(t, "initiator", issued.Metadata["role"])
	assert.Equal(t, "DPoP", issued.Metadata["token_type"])
	flat := fmt.Sprintf("%v", w.audit.Events())
	assert.NotContains(t, flat, proof, "the DPoP proof never enters the audit")
	assert.NotContains(t, flat, body["access_token"].(string), "the token never enters the audit")
	assert.Empty(t, w.refusals())
}

func TestTokenAgentComm_LegacyClientCredentialsUntouched(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(&service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: "plain-client", AllowedScopes: []string{"read"}})
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}
	rec := postToken(t, r, form, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := tokenJSON(t, rec)
	assert.Equal(t, "Bearer", body["token_type"], "without authorization_details the pre-existing path answers exactly as before")
	assert.Equal(t, 1, w.minter.calls)
	_, hasCnf := w.minter.last.Extra["cnf"]
	assert.False(t, hasCnf)
}

func TestTokenAgentComm_RefusalMatrix(t *testing.T) {
	type tc struct {
		name       string
		form       func(w *acTokenWorld) url.Values
		dpop       func(w *acTokenWorld) string
		client     func(w *acTokenWorld) *service.AuthenticatedClient
		wantCode   int
		wantError  string
		wantReason string
	}
	def := func(w *acTokenWorld) url.Values { return w.tokenForm() }
	good := func(w *acTokenWorld) string { return mintDPoP(t, w.keyA, uuid.NewString()) }
	clA := func(w *acTokenWorld) *service.AuthenticatedClient { return w.authClient(w.clA1) }
	cases := []tc{
		{"no proof", def, func(*acTokenWorld) string { return "" }, clA, 400, "invalid_dpop_proof", "dpop_missing"},
		{"garbage proof", def, func(*acTokenWorld) string { return "x.y.z" }, clA, 400, "invalid_dpop_proof", "dpop_invalid"},
		{"foreign proof key", def, func(w *acTokenWorld) string { return mintDPoP(t, newDPoPKey(t), uuid.NewString()) }, clA, 400, "invalid_dpop_proof", "thumbprint_mismatch"},
		{"other participant's ACI", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("authorization_details", acTokenDetails(w.auth.ID, w.aci(domain.AgentCommunicationRoleResponder)))
			return f
		}, good, clA, 400, "invalid_grant", "client_not_participant"},
		{"absent authorization", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			id, _ := uuid.NewV7()
			f.Set("authorization_details", acTokenDetails(id, w.aci(domain.AgentCommunicationRoleInitiator)))
			return f
		}, good, clA, 400, "invalid_grant", "authorization_not_found"},
		{"unknown detail type", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("authorization_details", `[{"type":"openid_credential","authorization_id":"x","aci":"y"}]`)
			return f
		}, good, clA, 400, "invalid_authorization_details", "invalid_authorization_details"},
		{"malformed details", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("authorization_details", `{"type":"agent_communication"}`)
			return f
		}, good, clA, 400, "invalid_authorization_details", "invalid_authorization_details"},
		{"audience mismatch", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("audience", "https://relay.example.test/other")
			return f
		}, good, clA, 400, "invalid_target", "audience_mismatch"},
		{"foreign scope", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("scope", "openid")
			return f
		}, good, clA, 400, "invalid_scope", "scope_invalid"},
		{"wrong grant type", func(w *acTokenWorld) url.Values {
			f := w.tokenForm()
			f.Set("grant_type", "refresh_token")
			return f
		}, good, clA, 400, "unsupported_grant_type", "unsupported_grant"},
		{"the other participant's client", def, good, func(w *acTokenWorld) *service.AuthenticatedClient { return w.authClient(w.clA2) }, 400, "invalid_grant", "client_not_participant"},
		{"another organization's client", def, good, func(w *acTokenWorld) *service.AuthenticatedClient { return w.authClient(w.clB1) }, 400, "invalid_grant", "authorization_not_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newACTokenWorld(t)
			rec := postToken(t, w.engine(c.client(w)), c.form(w), c.dpop(w))
			require.Equal(t, c.wantCode, rec.Code, rec.Body.String())
			body := tokenJSON(t, rec)
			assert.Equal(t, c.wantError, body["error"])
			_, hasToken := body["access_token"]
			assert.False(t, hasToken, "a refusal never carries a token")
			assert.Equal(t, 0, w.minter.calls, "nothing minted")
			refusals := w.refusals()
			require.Len(t, refusals, 1, "exactly one refusal audit event")
			assert.Equal(t, c.wantReason, refusals[0].Metadata["reason"])
			assert.Equal(t, "refused", refusals[0].Outcome)
		})
	}

	t.Run("unauthenticated client → invalid_client, untouched", func(t *testing.T) {
		w := newACTokenWorld(t)
		rec := postToken(t, w.engine(nil), w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid_client", tokenJSON(t, rec)["error"])
	})
}

func TestTokenAgentComm_StoreErrorIs503NotAVerdict(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))
	w.repo.fail = fmt.Errorf("dial tcp 10.0.0.9:5432: connect: connection refused")
	rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	body := tokenJSON(t, rec)
	assert.Equal(t, "temporarily_unavailable", body["error"])
	assert.Equal(t, "auth_store_error", body["reason"])
	assert.NotEmpty(t, body["correlation_id"])
	assert.Equal(t, body["correlation_id"], rec.Header().Get(mw.CorrelationIDHeader))
	assert.Equal(t, 0, w.minter.calls)
	assert.Empty(t, w.refusals(), "an outage is not a refusal verdict — no refusal is audited")
}
