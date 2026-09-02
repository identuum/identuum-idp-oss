package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ── fakes ─────────────────────────────────────────────────────────────────

type acTestRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.AgentCommunicationAuthorization
	fail error
}

func cloneACForHandlers(a *domain.AgentCommunicationAuthorization) *domain.AgentCommunicationAuthorization {
	c := *a
	c.Participants = append([]domain.AgentCommunicationParticipant(nil), a.Participants...)
	for i := range c.Participants {
		caps := make([]domain.AgentCommunicationCapability, len(a.Participants[i].Capabilities))
		copy(caps, a.Participants[i].Capabilities)
		c.Participants[i].Capabilities = caps
	}
	return &c
}

func (f *acTestRepo) Create(_ context.Context, a *domain.AgentCommunicationAuthorization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.rows[a.ID] = cloneACForHandlers(a)
	return nil
}

func (f *acTestRepo) GetByID(_ context.Context, org, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	row, ok := f.rows[id]
	if !ok || row.OrganizationID != org {
		return nil, domain.ErrAgentCommunicationAuthorizationNotFound
	}
	return cloneACForHandlers(row), nil
}

func (f *acTestRepo) ListByOrganization(_ context.Context, org uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	var out []*domain.AgentCommunicationAuthorization
	for _, row := range f.rows {
		if row.OrganizationID == org {
			out = append(out, cloneACForHandlers(row))
		}
	}
	return out, nil
}

func (f *acTestRepo) Revoke(_ context.Context, org, id, by uuid.UUID, reason *string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return false, f.fail
	}
	row, ok := f.rows[id]
	if !ok || row.OrganizationID != org || row.RevokedAt != nil {
		return false, nil
	}
	row.RevokedAt = &at
	row.RevokedBy = &by
	row.RevocationReason = reason
	return true, nil
}

type acTestSAs struct {
	rows map[uuid.UUID]*domain.ServiceAccount
	fail error
}

func (f *acTestSAs) GetByID(_ context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	sa, ok := f.rows[id]
	if !ok {
		return nil, domain.ErrServiceAccountNotFound
	}
	return sa, nil
}

type acTestClients struct {
	rows map[string]*domain.Client
	fail error
}

func (f *acTestClients) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	c, ok := f.rows[clientID]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	return c, nil
}

// acTestWorld is two organizations (A, B), an org_admin in each owning two
// agent identities, a site_admin and an org_user of A.
type acTestWorld struct {
	repo    *acTestRepo
	sas     *acTestSAs
	clients *acTestClients
	svc     *service.AgentCommunicationAuthorizationService
	rec     *audit.Recorder
	now     time.Time

	orgA, orgB     uuid.UUID
	adminA, adminB *domain.Principal
	siteAdmin      *domain.Principal
	userA          *domain.Principal
	saA1, saA2     *domain.ServiceAccount
	saB1, saB2     *domain.ServiceAccount
	clA1, clA2     *domain.Client
	clB1, clB2     *domain.Client
}

const (
	acThumbA = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	acThumbB = "0ZO2hCQ7O9O3HrCMNDbdb-MRyhAg8CTt3xfsq5c5C1w"
)

func acPrincipal(role domain.UserRole, org uuid.UUID, email string) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           role,
		Scope:          domain.SessionScopesForRole(role),
		Email:          email,
	}
}

func newACWorld(t *testing.T) *acTestWorld {
	t.Helper()
	w := &acTestWorld{
		repo:    &acTestRepo{rows: map[uuid.UUID]*domain.AgentCommunicationAuthorization{}},
		sas:     &acTestSAs{rows: map[uuid.UUID]*domain.ServiceAccount{}},
		clients: &acTestClients{rows: map[string]*domain.Client{}},
		rec:     &audit.Recorder{},
		now:     time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		orgA:    uuid.New(),
		orgB:    uuid.New(),
	}
	w.adminA = acPrincipal(domain.RoleOrgAdmin, w.orgA, "admin-a@a.test")
	w.adminB = acPrincipal(domain.RoleOrgAdmin, w.orgB, "admin-b@b.test")
	w.siteAdmin = acPrincipal(domain.RoleSiteAdmin, uuid.Nil, "site_admin@system.local")
	w.userA = acPrincipal(domain.RoleOrgUser, w.orgA, "user-a@a.test")

	mkSA := func(name string, org uuid.UUID, owner uuid.UUID) *domain.ServiceAccount {
		o := owner
		sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: org, Name: name, Active: true, OwnerUserID: &o}
		w.sas.rows[sa.ID] = sa
		return sa
	}
	mkClient := func(clientID string, sa *domain.ServiceAccount) *domain.Client {
		org := sa.OrganizationID
		saID := sa.ID
		c := &domain.Client{ID: uuid.New(), ClientID: clientID, OrganizationID: &org, ServiceAccountID: &saID,
			TokenEndpointAuthMethod: "private_key_jwt", JWKS: `{"keys":[]}`}
		w.clients.rows[clientID] = c
		return c
	}
	w.saA1 = mkSA("agent-a1", w.orgA, w.adminA.UserID)
	w.saA2 = mkSA("agent-a2", w.orgA, w.adminA.UserID)
	w.saB1 = mkSA("agent-b1", w.orgB, w.adminB.UserID)
	w.saB2 = mkSA("agent-b2", w.orgB, w.adminB.UserID)
	w.clA1 = mkClient("agent-a1-client", w.saA1)
	w.clA2 = mkClient("agent-a2-client", w.saA2)
	w.clB1 = mkClient("agent-b1-client", w.saB1)
	w.clB2 = mkClient("agent-b2-client", w.saB2)

	report := lifecycle.NewStartupReport()
	w.svc = service.NewAgentCommunicationAuthorizationService(report, w.repo, w.sas, w.clients,
		service.AgentCommunicationAuthorizationServiceOptions{Now: func() time.Time { return w.now }})
	require.False(t, report.HasFatal())
	return w
}

// engine mounts the surface behind the correlation-id middleware (as the
// production router does) and, when principal != nil, an injected bearer
// principal.
func (w *acTestWorld) engine(principal *domain.Principal) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.CorrelationIDMiddleware())
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	RegisterAgentCommunicationAuthorizationRoutes(r, AgentCommunicationAuthorizationsHandlerDeps{
		Service: w.svc,
		Audit:   w.rec,
	})
	return r
}

func (w *acTestWorld) createBody(sa1 *domain.ServiceAccount, cl1 *domain.Client, sa2 *domain.ServiceAccount, cl2 *domain.Client) map[string]any {
	return map[string]any{
		"relay_audience":         "https://relay.example.test/session",
		"expires_at":             w.now.Add(time.Hour).Format(time.RFC3339),
		"max_messages":           10,
		"max_message_size_bytes": 4096,
		"participants": []map[string]any{
			{"service_account_id": sa1.ID.String(), "client_id": cl1.ClientID, "role": "initiator",
				"proof_key_thumbprint": acThumbA, "capabilities": []string{"repository.read", "communication.discuss"}},
			{"service_account_id": sa2.ID.String(), "client_id": cl2.ClientID, "role": "responder",
				"proof_key_thumbprint": acThumbB, "capabilities": []string{}},
		},
	}
}

func (w *acTestWorld) bodyA() map[string]any { return w.createBody(w.saA1, w.clA1, w.saA2, w.clA2) }

// seed creates an authorization directly through the service (no HTTP, no
// audit) so probes have a row to aim at.
func (w *acTestWorld) seed(t *testing.T, actor *domain.Principal, sa1 *domain.ServiceAccount, cl1 *domain.Client, sa2 *domain.ServiceAccount, cl2 *domain.Client) *domain.AgentCommunicationAuthorization {
	t.Helper()
	a, err := w.svc.CreateForActor(context.Background(), actor, service.CreateAgentCommunicationAuthorizationInput{
		RelayAudience: "https://relay.example.test/seed", ExpiresAt: w.now.Add(time.Hour), MaxMessages: 5, MaxMessageSizeBytes: 1024,
		Participants: []service.AgentCommunicationParticipantInput{
			{ServiceAccountID: sa1.ID, ClientID: cl1.ClientID, Role: domain.AgentCommunicationRoleInitiator, ProofKeyThumbprint: acThumbA},
			{ServiceAccountID: sa2.ID, ClientID: cl2.ClientID, Role: domain.AgentCommunicationRoleResponder, ProofKeyThumbprint: acThumbB},
		},
	})
	require.NoError(t, err)
	return a
}

func acDo(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Reader
	if body == nil {
		buf = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func acJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), "body: %s", rec.Body.String())
	return m
}

const acBase = "/api/v1/agent-communication-authorizations"

// ── tests ─────────────────────────────────────────────────────────────────

func TestAgentCommAPI_Create_HappyPath(t *testing.T) {
	w := newACWorld(t)
	r := w.engine(w.adminA)
	rec := acDo(t, r, http.MethodPost, acBase, w.bodyA())
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	body := acJSON(t, rec)

	id, err := uuid.Parse(body["id"].(string))
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(7), id.Version())
	sess, err := uuid.Parse(body["session_id"].(string))
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(7), sess.Version())
	assert.Equal(t, w.orgA.String(), body["organization_id"])
	assert.Equal(t, w.adminA.UserID.String(), body["owner_id"], "the owner is the acting org_admin")
	assert.Equal(t, "active", body["status"])
	assert.Equal(t, "v1", body["policy_version"])
	assert.Len(t, body["policy_digest"].(string), 64)
	assert.Equal(t, "https://relay.example.test/session", body["relay_audience"])
	assert.Nil(t, body["revoked_at"])

	parts := body["participants"].([]any)
	require.Len(t, parts, 2)
	acis := map[string]bool{}
	for _, p := range parts {
		pm := p.(map[string]any)
		aci, err := uuid.Parse(pm["aci"].(string))
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), aci.Version())
		acis[aci.String()] = true
		assert.NotEmpty(t, pm["proof_key_thumbprint"])
		assert.NotNil(t, pm["capabilities"])
		for _, forbidden := range []string{"client_secret", "private_key", "jwks", "secret", "token"} {
			_, present := pm[forbidden]
			assert.False(t, present, "participant must not carry %q", forbidden)
		}
	}
	assert.Len(t, acis, 2, "distinct ACIs")
	for _, forbidden := range []string{"client_secret", "private_key", "jwks", "access_token", "dpop"} {
		_, present := body[forbidden]
		assert.False(t, present, "response must not carry %q", forbidden)
	}

	// The stored row is the returned one.
	stored, err := w.svc.Get(context.Background(), w.orgA, id)
	require.NoError(t, err)
	assert.Equal(t, body["policy_digest"], stored.PolicyDigest)
}

func TestAgentCommAPI_Create_IgnoresClientSuppliedServerFields(t *testing.T) {
	w := newACWorld(t)
	r := w.engine(w.adminA)
	body := w.bodyA()
	body["id"] = "00000000-0000-0000-0000-000000000001"
	body["session_id"] = "00000000-0000-0000-0000-000000000002"
	body["policy_digest"] = "deadbeef"
	body["owner_id"] = uuid.New().String()
	body["created_at"] = "2000-01-01T00:00:00Z"
	parts := body["participants"].([]map[string]any)
	parts[0]["aci"] = "00000000-0000-0000-0000-000000000003"
	parts[0]["id"] = "00000000-0000-0000-0000-000000000004"

	rec := acDo(t, r, http.MethodPost, acBase, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	got := acJSON(t, rec)
	assert.NotEqual(t, body["id"], got["id"])
	assert.NotEqual(t, body["session_id"], got["session_id"])
	assert.NotEqual(t, "deadbeef", got["policy_digest"])
	assert.Equal(t, w.adminA.UserID.String(), got["owner_id"])
	assert.Equal(t, w.now.Format(time.RFC3339), got["created_at"].(string)[:20], "created_at is server time")
	stored, err := w.svc.Get(context.Background(), w.orgA, uuid.MustParse(got["id"].(string)))
	require.NoError(t, err)
	recomputed, err := stored.ComputePolicyDigest()
	require.NoError(t, err)
	assert.Equal(t, recomputed, got["policy_digest"], "the digest is server-computed from the canonical policy")
	for _, p := range got["participants"].([]any) {
		assert.NotEqual(t, "00000000-0000-0000-0000-000000000003", p.(map[string]any)["aci"])
	}
}

func TestAgentCommAPI_Create_RefusalStatuses(t *testing.T) {
	cases := []struct {
		name       string
		mut        func(w *acTestWorld, body map[string]any)
		wantCode   int
		wantError  string
		wantReason string
	}{
		{"one participant", func(_ *acTestWorld, b map[string]any) { b["participants"] = b["participants"].([]map[string]any)[:1] }, 400, "invalid_request", "participant_count"},
		{"three participants", func(w *acTestWorld, b map[string]any) {
			p := b["participants"].([]map[string]any)
			b["participants"] = append(p, map[string]any{"service_account_id": w.saB1.ID.String(), "client_id": w.clB1.ClientID, "role": "responder", "proof_key_thumbprint": acThumbA})
		}, 400, "invalid_request", "participant_count"},
		{"unknown capability", func(_ *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["capabilities"] = []string{"repository.read", "repository.delete"}
		}, 400, "invalid_request", "unknown_capability"},
		{"duplicate role", func(_ *acTestWorld, b map[string]any) { b["participants"].([]map[string]any)[1]["role"] = "initiator" }, 400, "invalid_request", "duplicate_role"},
		{"invalid role", func(_ *acTestWorld, b map[string]any) { b["participants"].([]map[string]any)[1]["role"] = "observer" }, 400, "invalid_request", "invalid_role"},
		{"malformed service account id", func(_ *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["service_account_id"] = "not-a-uuid"
		}, 400, "invalid_request", "invalid_service_account_id"},
		{"absent service account", func(_ *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["service_account_id"] = uuid.New().String()
		}, 400, "invalid_request", "participant_service_account_not_found"},
		{"another organization's service account answers like an absent one", func(w *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["service_account_id"] = w.saB1.ID.String()
		}, 400, "invalid_request", "participant_service_account_not_found"},
		{"absent client", func(_ *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["client_id"] = "nobody"
		}, 400, "invalid_request", "participant_client_not_found"},
		{"client not bound to the participant", func(w *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["client_id"] = w.clA2.ClientID
			b["participants"].([]map[string]any)[1]["client_id"] = w.clA1.ClientID
		}, 400, "invalid_request", "client_not_bound"},
		{"client without private_key_jwt", func(w *acTestWorld, _ map[string]any) { w.clA2.TokenEndpointAuthMethod = "client_secret_basic" }, 400, "invalid_request", "client_auth_not_asymmetric"},
		{"ownerless participant", func(w *acTestWorld, _ map[string]any) { w.saA2.OwnerUserID = nil }, 403, "forbidden", "ownerless_participant"},
		{"participant owned by another admin", func(w *acTestWorld, _ map[string]any) { other := uuid.New(); w.saA1.OwnerUserID = &other }, 403, "forbidden", "owner_mismatch"},
		{"inactive participant", func(w *acTestWorld, _ map[string]any) { w.saA1.Active = false }, 409, "conflict", "participant_not_usable"},
		{"expiry in the past", func(w *acTestWorld, b map[string]any) { b["expires_at"] = w.now.Add(-time.Minute).Format(time.RFC3339) }, 400, "invalid_request", "expiry_not_future"},
		{"zero limit", func(_ *acTestWorld, b map[string]any) { b["max_messages"] = 0 }, 400, "invalid_request", "limit_not_positive"},
		{"empty audience", func(_ *acTestWorld, b map[string]any) { b["relay_audience"] = "  " }, 400, "invalid_request", "relay_audience_required"},
		{"bad thumbprint", func(_ *acTestWorld, b map[string]any) {
			b["participants"].([]map[string]any)[0]["proof_key_thumbprint"] = "a/b"
		}, 400, "invalid_request", "proof_key_thumbprint_invalid"},
		{"explicit foreign organization", func(w *acTestWorld, b map[string]any) { b["organization_id"] = w.orgB.String() }, 403, "forbidden", ""},
		{"malformed organization id", func(_ *acTestWorld, b map[string]any) { b["organization_id"] = "nope" }, 400, "invalid_request", "invalid_organization_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newACWorld(t)
			body := w.bodyA()
			tc.mut(w, body)
			rec := acDo(t, w.engine(w.adminA), http.MethodPost, acBase, body)
			require.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
			got := acJSON(t, rec)
			assert.Equal(t, tc.wantError, got["error"])
			if tc.wantReason != "" {
				assert.Equal(t, tc.wantReason, got["reason"])
			}
			assert.Equal(t, 0, w.rec.Len(), "a refused create records no audit event")
			assert.Empty(t, w.repo.rows, "nothing persisted")
		})
	}

	t.Run("malformed JSON", func(t *testing.T) {
		w := newACWorld(t)
		req := httptest.NewRequest(http.MethodPost, acBase, bytes.NewReader([]byte(`{"relay_audience": `)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		w.engine(w.adminA).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestAgentCommAPI_Unauthenticated_Is401OnEveryRoute(t *testing.T) {
	w := newACWorld(t)
	r := w.engine(nil)
	id := uuid.New().String()
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, acBase}, {http.MethodGet, acBase}, {http.MethodGet, acBase + "/" + id}, {http.MethodPost, acBase + "/" + id + "/revoke"},
	} {
		rec := acDo(t, r, probe.method, probe.path, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s", probe.method, probe.path)
	}
}

func TestAgentCommAPI_GetListRevoke(t *testing.T) {
	w := newACWorld(t)
	r := w.engine(w.adminA)
	a := w.seed(t, w.adminA, w.saA1, w.clA1, w.saA2, w.clA2)

	rec := acDo(t, r, http.MethodGet, acBase+"/"+a.ID.String(), nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, a.ID.String(), acJSON(t, rec)["id"])

	rec = acDo(t, r, http.MethodGet, acBase+"/not-a-uuid", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_authorization_id", acJSON(t, rec)["reason"])

	rec = acDo(t, r, http.MethodGet, acBase, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	list := acJSON(t, rec)
	assert.EqualValues(t, 1, list["count"])
	assert.Len(t, list["authorizations"].([]any), 1)

	// Revoke without a body, then with a reason (idempotent).
	w.now = w.now.Add(time.Minute)
	rec = acDo(t, r, http.MethodPost, acBase+"/"+a.ID.String()+"/revoke", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	first := acJSON(t, rec)
	assert.Equal(t, "revoked", first["status"])
	assert.Equal(t, w.adminA.UserID.String(), first["revoked_by"])
	assert.NotEmpty(t, first["revoked_at"])
	assert.Nil(t, first["revocation_reason"])

	rec = acDo(t, r, http.MethodPost, acBase+"/"+a.ID.String()+"/revoke", map[string]any{"reason": "later"})
	require.Equal(t, http.StatusOK, rec.Code)
	second := acJSON(t, rec)
	assert.Equal(t, first["revoked_at"], second["revoked_at"], "terminal: the first stamp stands")
	assert.Nil(t, second["revocation_reason"], "a later reason never overwrites the first stamp")

	// A bounded reason is stored on a fresh revoke; an oversized one is refused.
	b := w.seed(t, w.adminA, w.saA1, w.clA1, w.saA2, w.clA2)
	long := make([]byte, domain.AgentCommunicationRevocationReasonMaxLen+1)
	for i := range long {
		long[i] = 'x'
	}
	rec = acDo(t, r, http.MethodPost, acBase+"/"+b.ID.String()+"/revoke", map[string]any{"reason": string(long)})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "revocation_reason_too_long", acJSON(t, rec)["reason"])
	rec = acDo(t, r, http.MethodPost, acBase+"/"+b.ID.String()+"/revoke", map[string]any{"reason": "  operator request "})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "operator request", acJSON(t, rec)["revocation_reason"])
}

func TestAgentCommAPI_RoutesAbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAgentCommunicationAuthorizationRoutes(r, AgentCommunicationAuthorizationsHandlerDeps{})
	rec := acDo(t, r, http.MethodGet, acBase, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, "no service → no routes")
}
