package handlers

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// THE-OWNERLESS-ACCOUNT: the wire behavior of
// POST /api/v1/service-accounts/:id/owner.

// saOwnerUsers is the candidate-owner lookup: a tiny user directory.
type saOwnerUsers struct {
	rows map[uuid.UUID]*domain.User
	err  error
}

func (f *saOwnerUsers) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	u, ok := f.rows[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

// saOwnerLive answers the live-authorization guard.
type saOwnerLive struct {
	live bool
	err  error
	// seen records the arguments so a test can prove the guard was asked
	// about the right account.
	seen []string
}

func (f *saOwnerLive) HasLiveParticipant(_ context.Context, org, sa uuid.UUID, now time.Time) (bool, error) {
	f.seen = append(f.seen, org.String()+"/"+sa.String())
	if f.err != nil {
		return false, f.err
	}
	return f.live, nil
}

type saOwnerWorld struct {
	repo  *inMemorySARepoForHandlers
	users *saOwnerUsers
	live  *saOwnerLive
	rec   *audit.Recorder
	svc   *service.ServiceAccountService
	org   uuid.UUID
	admin *domain.Principal
	other *domain.Principal
	sa    *domain.ServiceAccount
}

func newSAOwnerWorld(t *testing.T) *saOwnerWorld {
	t.Helper()
	w := &saOwnerWorld{
		repo:  newSARepoForHandlers(),
		users: &saOwnerUsers{rows: map[uuid.UUID]*domain.User{}},
		live:  &saOwnerLive{},
		rec:   &audit.Recorder{},
		org:   uuid.New(),
	}
	w.admin = saOrgAdminPrincipal(w.org)
	w.other = saOrgAdminPrincipal(w.org)
	w.users.rows[w.admin.UserID] = &domain.User{ID: w.admin.UserID, OrganizationID: w.org, Role: domain.RoleOrgAdmin}
	w.users.rows[w.other.UserID] = &domain.User{ID: w.other.UserID, OrganizationID: w.org, Role: domain.RoleOrgAdmin}
	w.svc = service.NewServiceAccountService(nil, w.repo).WithOwnerAssignment(w.users, w.live)
	sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: w.org, Name: "agent", Active: true}
	w.repo.byID[sa.ID] = sa
	w.sa = sa
	return w
}

func (w *saOwnerWorld) engine(p *domain.Principal) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.CorrelationIDMiddleware())
	if p != nil {
		r.Use(mw.InjectPrincipalForTest(p))
	}
	RegisterServiceAccountsRoutes(r, ServiceAccountsHandlerDeps{ServiceAccountService: w.svc, Audit: w.rec})
	return r
}

// assignOwner posts the owner route. body nil sends no body at all.
func assignOwner(t *testing.T, r *gin.Engine, saID uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/service-accounts/" + saID.String() + "/owner"
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func ownerJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())
	return m
}

func (w *saOwnerWorld) ownerEvents() []audit.Event {
	out := []audit.Event{}
	for _, e := range w.rec.Events() {
		if e.Action == AuditActionServiceAccountOwnerAssigned {
			out = append(out, e)
		}
	}
	return out
}

func TestSAOwner_AssignClaimsForTheActingAdmin(t *testing.T) {
	w := newSAOwnerWorld(t)
	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := ownerJSON(t, rec)
	assert.Equal(t, w.sa.ID.String(), body["service_account_id"])
	assert.Equal(t, w.admin.UserID.String(), body["owner_user_id"])
	assert.Nil(t, body["previous_owner_user_id"], "there was no owner")
	assert.Equal(t, "assigned", body["result"])
	require.NotNil(t, w.repo.byID[w.sa.ID].OwnerUserID)
	assert.Equal(t, w.admin.UserID, *w.repo.byID[w.sa.ID].OwnerUserID)

	events := w.ownerEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "", events[0].Metadata["previous_owner_user_id"])
	assert.Equal(t, w.admin.UserID.String(), events[0].Metadata["owner_user_id"])
	assert.Equal(t, "assigned", events[0].Metadata["result"])
	assert.Equal(t, w.org, events[0].OrganizationID)
	assert.Empty(t, w.live.seen, "an assignment with no previous owner asks no guard")
}

func TestSAOwner_TransferToAnotherOrgAdminRecordsBeforeAndAfter(t *testing.T) {
	w := newSAOwnerWorld(t)
	first := w.admin.UserID
	w.repo.byID[w.sa.ID].OwnerUserID = &first

	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, map[string]any{"owner_user_id": w.other.UserID.String()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := ownerJSON(t, rec)
	assert.Equal(t, first.String(), body["previous_owner_user_id"])
	assert.Equal(t, w.other.UserID.String(), body["owner_user_id"])
	assert.Equal(t, "transferred", body["result"])
	require.Len(t, w.live.seen, 1, "the guard is asked exactly once, about this account")
	assert.Equal(t, w.org.String()+"/"+w.sa.ID.String(), w.live.seen[0])

	events := w.ownerEvents()
	require.Len(t, events, 1)
	assert.Equal(t, first.String(), events[0].Metadata["previous_owner_user_id"])
	assert.Equal(t, w.other.UserID.String(), events[0].Metadata["owner_user_id"])
	assert.Equal(t, "transferred", events[0].Metadata["result"])
}

func TestSAOwner_ReassigningTheSameOwnerWritesNothing(t *testing.T) {
	w := newSAOwnerWorld(t)
	first := w.admin.UserID
	w.repo.byID[w.sa.ID].OwnerUserID = &first

	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, map[string]any{"owner_user_id": first.String()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "unchanged", ownerJSON(t, rec)["result"])
	assert.Empty(t, w.ownerEvents(), "an unchanged binding is not an ownership event")
	assert.Empty(t, w.live.seen, "nothing moves, so nothing is guarded")
}

func TestSAOwner_IneligibleCandidatesAreRefusedIdentically(t *testing.T) {
	w := newSAOwnerWorld(t)
	deleted := uuid.New()
	when := time.Now()
	w.users.rows[deleted] = &domain.User{ID: deleted, OrganizationID: w.org, Role: domain.RoleOrgAdmin, DeletedAt: &when}
	banned := uuid.New()
	w.users.rows[banned] = &domain.User{ID: banned, OrganizationID: w.org, Role: domain.RoleOrgAdmin, Banned: true}
	orgUser := uuid.New()
	w.users.rows[orgUser] = &domain.User{ID: orgUser, OrganizationID: w.org, Role: domain.RoleOrgUser}
	foreign := uuid.New()
	w.users.rows[foreign] = &domain.User{ID: foreign, OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin}

	for name, candidate := range map[string]uuid.UUID{
		"deleted user":            deleted,
		"banned user":             banned,
		"org_user":                orgUser,
		"another org's org_admin": foreign,
		"unknown id":              uuid.New(),
	} {
		t.Run(name, func(t *testing.T) {
			rec := assignOwner(t, w.engine(w.admin), w.sa.ID, map[string]any{"owner_user_id": candidate.String()})
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			body := ownerJSON(t, rec)
			assert.Equal(t, "invalid_request", body["error"])
			assert.Equal(t, "owner_not_eligible", body["reason"], "every ineligible candidate answers identically")
			assert.Nil(t, w.repo.byID[w.sa.ID].OwnerUserID)
		})
	}
	assert.Empty(t, w.ownerEvents())
}

func TestSAOwner_ForeignAndAbsentAnswerNotFoundIdentically(t *testing.T) {
	w := newSAOwnerWorld(t)
	foreignAdmin := saOrgAdminPrincipal(uuid.New())

	absent := assignOwner(t, w.engine(w.admin), uuid.New(), nil)
	foreign := assignOwner(t, w.engine(foreignAdmin), w.sa.ID, nil)
	require.Equal(t, http.StatusNotFound, absent.Code)
	require.Equal(t, http.StatusNotFound, foreign.Code)
	assert.Equal(t, absent.Body.String(), foreign.Body.String(), "no cross-tenant existence oracle")
}

func TestSAOwner_OrgUserIsRefused(t *testing.T) {
	w := newSAOwnerWorld(t)
	user := &domain.Principal{UserID: uuid.New(), OrganizationID: w.org, Role: domain.RoleOrgUser}
	rec := assignOwner(t, w.engine(user), w.sa.ID, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Nil(t, w.repo.byID[w.sa.ID].OwnerUserID)
}

func TestSAOwner_SiteAdminIsRefused(t *testing.T) {
	w := newSAOwnerWorld(t)
	site := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	rec := assignOwner(t, w.engine(site), w.sa.ID, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String(),
		"service accounts are a tenant's own resource (AdminPermissionsModel.md)")
}

func TestSAOwner_UnauthenticatedIs401(t *testing.T) {
	w := newSAOwnerWorld(t)
	rec := assignOwner(t, w.engine(nil), w.sa.ID, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSAOwner_MalformedBodyAndIDAre400(t *testing.T) {
	w := newSAOwnerWorld(t)
	r := w.engine(w.admin)

	bad := httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/"+w.sa.ID.String()+"/owner", strings.NewReader("{"))
	bad.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, bad)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_body", ownerJSON(t, rec)["reason"])

	rec = assignOwner(t, r, w.sa.ID, map[string]any{"owner_user_id": "not-a-uuid"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_owner_user_id", ownerJSON(t, rec)["reason"])
}

func TestSAOwner_GuardStoreErrorIs503(t *testing.T) {
	w := newSAOwnerWorld(t)
	first := w.admin.UserID
	w.repo.byID[w.sa.ID].OwnerUserID = &first
	w.live.err = errors.New("db down")

	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, map[string]any{"owner_user_id": w.other.UserID.String()})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.NotEmpty(t, ownerJSON(t, rec)["correlation_id"], rec.Body.String())
	assert.Equal(t, first, *w.repo.byID[w.sa.ID].OwnerUserID, "nothing moved")
}

func TestSAOwner_TransferWithoutTheGuardWiredRefusesToAnswer(t *testing.T) {
	w := newSAOwnerWorld(t)
	first := w.admin.UserID
	w.repo.byID[w.sa.ID].OwnerUserID = &first
	// A service built without the guard cannot evaluate the invariant, so it
	// answers 503 rather than transferring blind.
	w.svc = service.NewServiceAccountService(nil, w.repo).WithOwnerAssignment(w.users, nil)

	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, map[string]any{"owner_user_id": w.other.UserID.String()})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, first, *w.repo.byID[w.sa.ID].OwnerUserID)
}

func TestSAOwner_AssignmentStillWorksWithoutTheGuard(t *testing.T) {
	w := newSAOwnerWorld(t)
	w.svc = service.NewServiceAccountService(nil, w.repo).WithOwnerAssignment(w.users, nil)
	rec := assignOwner(t, w.engine(w.admin), w.sa.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "assigned", ownerJSON(t, rec)["result"],
		"an account with no owner has no live authorization to protect")
}
