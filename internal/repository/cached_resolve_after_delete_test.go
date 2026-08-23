package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deleting a client or an identity provider evicts every cache key it can be
// resolved through, so a deleted client or identity provider never resolves
// from the cache — the next resolve consults the database. SOFTDEL-RESOLVE-1
// pins this at the DB layer; this pins the lookaside layer above it. Seeding
// goes THROUGH the public reads (miss → delegate → cached; second read is a
// proven hit against a .Once delegate expectation), so every assertion is
// about what the SERVING path returns, not which keys exist.
// RULE: CACHE-RESOLVE-DELETE-1
func TestCachedRepositories_DeletedNeverResolvesFromCache(t *testing.T) {
	mr, rdb := setupTestRedis(t)
	defer mr.Close()
	ctx := context.Background()

	// ---- Client layer: both resolve paths (client_id string, internal id) ----
	clientMock := new(mockClientRepository)
	clients := NewCachedClientRepository(clientMock, rdb, 5*time.Minute)
	c := &domain.Client{ID: uuid.New(), ClientID: "resolve-after-delete-client"}

	clientMock.On("GetClientByClientID", ctx, c.ClientID).Return(c, nil).Once()
	got, err := clients.GetClientByClientID(ctx, c.ClientID)
	require.NoError(t, err)
	require.Equal(t, c.ID, got.ID)
	got, err = clients.GetClientByClientID(ctx, c.ClientID)
	require.NoError(t, err)
	require.Equal(t, c.ID, got.ID)

	clientMock.On("GetClientByID", ctx, c.ID).Return(c, nil).Once()
	got, err = clients.GetClientByID(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, c.ID, got.ID)
	got, err = clients.GetClientByID(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, c.ID, got.ID)

	// Delete pre-fetches the row through the delegate, deletes, and must then
	// evict every key the client resolves through.
	clientMock.On("GetClientByID", ctx, c.ID).Return(c, nil).Once()
	clientMock.On("Delete", ctx, c.ID, (*uuid.UUID)(nil)).Return(nil).Once()
	require.NoError(t, clients.Delete(ctx, c.ID, nil))

	clientMock.On("GetClientByClientID", ctx, c.ClientID).
		Return((*domain.Client)(nil), fmt.Errorf("client deleted")).Once()
	_, err = clients.GetClientByClientID(ctx, c.ClientID)
	assert.Error(t, err,
		"deleted client must not resolve from cache: GetClientByClientID served a cache remnant")

	clientMock.On("GetClientByID", ctx, c.ID).
		Return((*domain.Client)(nil), fmt.Errorf("client deleted")).Once()
	_, err = clients.GetClientByID(ctx, c.ID)
	assert.Error(t, err,
		"deleted client must not resolve from cache: GetClientByID served a cache remnant")

	clientMock.AssertExpectations(t)

	// ---- Identity-provider layer: id, org+type (HRD login path), org list ----
	idpMock := new(mockIdentityProviderRepository)
	idps := NewCachedIdentityProviderRepository(idpMock, rdb, 5*time.Minute)
	p := &domain.IdentityProvider{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Type:           domain.IdentityProviderType("oidc"),
	}

	idpMock.On("GetByID", ctx, p.ID).Return(p, nil).Once()
	gp, err := idps.GetByID(ctx, p.ID)
	require.NoError(t, err)
	require.Equal(t, p.ID, gp.ID)
	gp, err = idps.GetByID(ctx, p.ID)
	require.NoError(t, err)
	require.Equal(t, p.ID, gp.ID)

	idpMock.On("GetByOrgAndType", ctx, p.OrganizationID, p.Type).Return(p, nil).Once()
	gp, err = idps.GetByOrgAndType(ctx, p.OrganizationID, p.Type)
	require.NoError(t, err)
	require.Equal(t, p.ID, gp.ID)
	gp, err = idps.GetByOrgAndType(ctx, p.OrganizationID, p.Type)
	require.NoError(t, err)
	require.Equal(t, p.ID, gp.ID)

	idpMock.On("ListByOrganization", ctx, p.OrganizationID).
		Return([]*domain.IdentityProvider{p}, nil).Once()
	lst, err := idps.ListByOrganization(ctx, p.OrganizationID)
	require.NoError(t, err)
	require.Len(t, lst, 1)
	lst, err = idps.ListByOrganization(ctx, p.OrganizationID)
	require.NoError(t, err)
	require.Len(t, lst, 1)

	idpMock.On("GetByID", ctx, p.ID).Return(p, nil).Once()
	idpMock.On("Delete", ctx, p.ID, p.OrganizationID).Return(nil).Once()
	require.NoError(t, idps.Delete(ctx, p.ID, p.OrganizationID))

	idpMock.On("GetByID", ctx, p.ID).
		Return((*domain.IdentityProvider)(nil), fmt.Errorf("idp deleted")).Once()
	_, err = idps.GetByID(ctx, p.ID)
	assert.Error(t, err,
		"deleted identity provider must not resolve from cache: GetByID served a cache remnant")

	idpMock.On("GetByOrgAndType", ctx, p.OrganizationID, p.Type).
		Return((*domain.IdentityProvider)(nil), fmt.Errorf("idp deleted")).Once()
	_, err = idps.GetByOrgAndType(ctx, p.OrganizationID, p.Type)
	assert.Error(t, err,
		"deleted identity provider must not resolve from cache: GetByOrgAndType (HRD login path) served a cache remnant")

	idpMock.On("ListByOrganization", ctx, p.OrganizationID).
		Return([]*domain.IdentityProvider{}, nil).Once()
	lst, err = idps.ListByOrganization(ctx, p.OrganizationID)
	require.NoError(t, err)
	assert.Empty(t, lst,
		"deleted identity provider must not resolve from cache: the org list served a cache remnant")

	idpMock.AssertExpectations(t)
}
