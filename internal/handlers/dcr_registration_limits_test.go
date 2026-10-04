package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A client registered with an initial access token keeps that token's limits
// on grant types and token-endpoint auth methods: an RFC 7592 update cannot
// add what the registration could not have. A client registered without one
// keeps the update's ordinary freedom.

type memRegistrationLimits struct {
	mu   sync.Mutex
	rows map[uuid.UUID]domain.DCRRegistrationLimits
}

func (m *memRegistrationLimits) SaveRegistrationLimits(_ context.Context, clientID uuid.UUID, l domain.DCRRegistrationLimits) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[clientID] = l
	return nil
}

func (m *memRegistrationLimits) RegistrationLimits(_ context.Context, clientID uuid.UUID) (*domain.DCRRegistrationLimits, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.rows[clientID]; ok {
		return &l, nil
	}
	return nil, nil
}

func newLimitsEngine(t *testing.T) (orgConfigEngine, *memRegistrationLimits) {
	t.Helper()
	eng := newOrgConfigEngine(t, nil, nil)
	limits := &memRegistrationLimits{rows: map[uuid.UUID]domain.DCRRegistrationLimits{}}
	clientSvc := service.NewClientService(nil, eng.clientRepo)
	gin.SetMode(gin.ReleaseMode)
	eng.r = gin.New()
	RegisterDCRRoutes(eng.r, DCRHandlerDeps{
		ClientService: clientSvc, IATService: eng.iatSvc, RATService: eng.ratSvc,
		RegistrationBaseURL: "https://idp.example.com", Audit: &audit.Recorder{}, RegistrationLimits: limits,
	})
	RegisterDCRManagementRoutes(eng.r, DCRManagementHandlerDeps{
		ClientService: clientSvc, RATService: eng.ratSvc, Audit: &audit.Recorder{}, RegistrationLimits: limits,
	})
	return eng, limits
}

func registerWithIAT(t *testing.T, eng orgConfigEngine, opts service.IssueOptions) (uuid.UUID, string) {
	t.Helper()
	res, err := eng.iatSvc.Issue(context.Background(), opts)
	if err != nil {
		t.Fatalf("Issue IAT: %v", err)
	}
	rec := orgConfigJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name": "Limited", "redirect_uris": []string{"https://rp.example.com/cb"},
		"grant_types": []string{"authorization_code"}, "token_endpoint_auth_method": "client_secret_basic",
	}, res.RawIAT)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	for id, c := range eng.clientRepo.rows {
		if c.ClientID == resp.ClientID {
			return id, resp.RegistrationAccessToken
		}
	}
	t.Fatal("registered client not found")
	return uuid.Nil, ""
}

func TestDCRManagementPut_KeepsTheInitialAccessTokensLimits(t *testing.T) {
	eng, _ := newLimitsEngine(t)
	id, rat := registerWithIAT(t, eng, service.IssueOptions{
		TTL: time.Hour, MaxUses: 1,
		AllowedGrantTypes:               []string{"authorization_code", "refresh_token"},
		AllowedTokenEndpointAuthMethods: []string{"client_secret_basic"},
	})
	path := "/api/v1/oauth/register/" + id.String()

	for name, body := range map[string]map[string]any{
		"a grant type the token forbade":   {"grant_types": []string{"authorization_code", "client_credentials"}},
		"an auth method the token forbade": {"token_endpoint_auth_method": "client_secret_post"},
	} {
		rec := orgConfigJSON(t, eng, http.MethodPut, path, body, rat)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d %s, want 403", name, rec.Code, rec.Body.String())
		}
	}
	if c := eng.clientRepo.rows[id]; len(c.GrantTypes) != 1 || c.GrantTypes[0] != "authorization_code" {
		t.Errorf("a refused update changed the grant types: %v", c.GrantTypes)
	}

	rec := orgConfigJSON(t, eng, http.MethodPut, path, map[string]any{"grant_types": []string{"authorization_code", "refresh_token"}}, rat)
	if rec.Code != http.StatusOK {
		t.Errorf("an update within the limits: status = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

func TestDCRManagementPut_AClientWithoutTokenLimitsIsUnrestricted(t *testing.T) {
	eng, _ := newLimitsEngine(t)
	id, rat := registerWithIAT(t, eng, service.IssueOptions{TTL: time.Hour, MaxUses: 1})
	rec := orgConfigJSON(t, eng, http.MethodPut, "/api/v1/oauth/register/"+id.String(),
		map[string]any{"grant_types": []string{"authorization_code", "client_credentials"}}, rat)
	if rec.Code != http.StatusOK {
		t.Errorf("an update of a client whose token set no limits: status = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
