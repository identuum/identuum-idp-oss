package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// THE-OWNERLESS-ACCOUNT rules.

// RULE: SA-OWNER-TRANSFER-LIVE-1
func TestRule_SA_OWNER_TRANSFER_LIVE_1(t *testing.T) {
	// One world, two surfaces: the agent-communication admin service holds a
	// LIVE authorization naming saA1, and the service-account service is
	// asked to move that account's owner. The guard is the REAL repository
	// predicate, not a boolean stub.
	acw := newACWorld(t)
	// The guard runs on the wall clock (the service-account service has no
	// clock seam), so the authorization must be live NOW.
	authorization, err := acw.svc.CreateForActor(context.Background(), acw.adminA, service.CreateAgentCommunicationAuthorizationInput{
		RelayAudience: "https://relay.example.test/session", ExpiresAt: time.Now().Add(time.Hour),
		MaxMessages: 10, MaxMessageSizeBytes: 4096,
		Participants: []service.AgentCommunicationParticipantInput{
			{ServiceAccountID: acw.saA1.ID, ClientID: acw.clA1.ClientID, Role: domain.AgentCommunicationRoleInitiator, ProofKeyThumbprint: acThumbA},
			{ServiceAccountID: acw.saA2.ID, ClientID: acw.clA2.ClientID, Role: domain.AgentCommunicationRoleResponder, ProofKeyThumbprint: acThumbB},
		},
	})
	require.NoError(t, err)
	require.Nil(t, authorization.RevokedAt)

	saRepo := newSARepoForHandlers()
	saRepo.byID[acw.saA1.ID] = acw.saA1
	saRepo.byID[acw.saA2.ID] = acw.saA2
	// A second, unrelated account of the same organization: nothing names it.
	free := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: acw.orgA, Name: "free", Active: true}
	owner := acw.adminA.UserID
	free.OwnerUserID = &owner
	saRepo.byID[free.ID] = free

	users := &saOwnerUsers{rows: map[uuid.UUID]*domain.User{
		acw.adminA.UserID: {ID: acw.adminA.UserID, OrganizationID: acw.orgA, Role: domain.RoleOrgAdmin},
	}}
	successor := saOrgAdminPrincipal(acw.orgA)
	users.rows[successor.UserID] = &domain.User{ID: successor.UserID, OrganizationID: acw.orgA, Role: domain.RoleOrgAdmin}

	rec := &audit.Recorder{}
	saSvc := service.NewServiceAccountService(nil, saRepo).WithOwnerAssignment(users, acw.repo)
	w := &saOwnerWorld{repo: saRepo, users: users, rec: rec, svc: saSvc, org: acw.orgA, admin: acw.adminA}
	engine := w.engine(acw.adminA)
	before := *acw.saA1.OwnerUserID

	// (1) A live authorization names saA1: the transfer is refused, with the
	// stable reason, and NOTHING moves.
	resp := assignOwner(t, engine, acw.saA1.ID, map[string]any{"owner_user_id": successor.UserID.String()})
	require.Equal(t, http.StatusConflict, resp.Code, resp.Body.String())
	body := ownerJSON(t, resp)
	assert.Equal(t, "conflict", body["error"])
	assert.Equal(t, "agent_communication_authorization_active", body["reason"])
	require.NotNil(t, saRepo.byID[acw.saA1.ID].OwnerUserID)
	assert.Equal(t, before, *saRepo.byID[acw.saA1.ID].OwnerUserID, "the owner of record is unchanged")

	// (2) The other participant is protected by the same authorization.
	resp = assignOwner(t, engine, acw.saA2.ID, map[string]any{"owner_user_id": successor.UserID.String()})
	assert.Equal(t, http.StatusConflict, resp.Code, resp.Body.String())

	// (3) An account no live authorization names transfers normally.
	resp = assignOwner(t, engine, free.ID, map[string]any{"owner_user_id": successor.UserID.String()})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, "transferred", ownerJSON(t, resp)["result"])

	// (4) Revoke the authorization — the owner's own remedy — and the same
	// transfer that was refused now proceeds.
	_, _, revokeErr := acw.svc.RevokeForActor(context.Background(), acw.adminA, authorization.ID, "handing the agent over")
	require.NoError(t, revokeErr)
	resp = assignOwner(t, engine, acw.saA1.ID, map[string]any{"owner_user_id": successor.UserID.String()})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, "transferred", ownerJSON(t, resp)["result"])
	assert.Equal(t, successor.UserID, *saRepo.byID[acw.saA1.ID].OwnerUserID)
}

// RULE: SA-STORE-503-1
func TestRule_SA_STORE_503_1(t *testing.T) {
	// (1) The admin surface: a store outage is 503 + a correlation id, and an
	// ABSENT account is still 404. The two must not look alike.
	w := newSAOwnerWorld(t)
	engine := w.engine(w.admin)

	absent := assignOwner(t, engine, uuid.New(), nil)
	require.Equal(t, http.StatusNotFound, absent.Code, "a genuine absence is still not-found")

	w.repo.getErr = errors.New("db down")
	for name, call := range map[string]func() *httptest.ResponseRecorder{
		"owner assignment": func() *httptest.ResponseRecorder {
			return assignOwner(t, engine, w.sa.ID, nil)
		},
		"read": func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/service-accounts/"+w.sa.ID.String(), nil)
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)
			return rec
		},
		"disable": func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/"+w.sa.ID.String()+"/disable", nil)
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)
			return rec
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := call()
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			body := ownerJSON(t, rec)
			assert.NotEmpty(t, body["correlation_id"], "AUTH-503 carries a correlation id")
		})
	}
	w.repo.getErr = nil

	// (2) The token endpoint: the same outage on the service-account lookup
	// answers 503, not unauthorized_client. A client with no service account
	// bound still gets the ordinary answer.
	tw := newACTokenWorld(t)
	saRepo := newSARepoForHandlers()
	bound := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: tw.orgA, Name: "bound", Active: true}
	saRepo.byID[bound.ID] = bound
	saID := bound.ID
	tw.clients.rows["sa-client"] = &domain.Client{
		ID: uuid.New(), ClientID: "sa-client", OrganizationID: &tw.orgA, ServiceAccountID: &saID,
	}
	report := lifecycle.NewStartupReport()
	tokens := service.NewTokenService(report, &handlerKeyProvider{}, service.TokenServiceOptions{
		Issuer: "https://idp.test", Minter: tw.minter,
	}).WithServiceAccountLookup(service.NewServiceAccountService(nil, saRepo), tw.clients)
	require.False(t, report.HasFatal())
	tw.tokens = tokens

	form := url.Values{"grant_type": {"client_credentials"}}
	client := &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: "sa-client"}

	ok := postToken(t, tw.engine(client), form, "")
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	saRepo.getErr = errors.New("db down")
	out := postToken(t, tw.engine(client), form, "")
	require.Equal(t, http.StatusServiceUnavailable, out.Code, out.Body.String())
	outBody := tokenJSON(t, out)
	assert.NotEmpty(t, outBody["correlation_id"])
	assert.NotEqual(t, "unauthorized_client", outBody["error"],
		"a store outage is not a verdict about the client")
}
