//go:build integration

package postgres_test

// The organization filter of the back-channel logout delivery list, against
// the live SQL (owner ruling, v0.9.5): it keeps only deliveries of live
// clients of that organization — never another organization's, never a
// deleted client's.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func TestBackchannelDeliveryList_OrganizationFilter(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgA := uuid.MustParse(seedScratchOrg(t, pool))
	orgB := uuid.MustParse(seedScratchOrg(t, pool))
	clients := postgres.NewPgxClientRepository(pool)
	deliveries := postgres.NewPgxBackchannelLogoutDeliveryRepository(pool)

	register := func(org uuid.UUID, name string) *domain.Client {
		t.Helper()
		c := &domain.Client{ID: uuid.New(), Name: name, OrganizationID: &org, RedirectURIs: []string{"https://bcl.example/cb"}}
		if err := clients.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	liveA, deletedA, liveB := register(orgA, "live-a"), register(orgA, "deleted-a"), register(orgB, "live-b")
	if err := clients.Delete(ctx, deletedA.ID, &orgA); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	insert := func(clientID string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if err := deliveries.Insert(ctx, &domain.BackchannelLogoutDelivery{
			ID: id, ClientID: clientID, LogoutJTI: uuid.NewString(), Status: domain.BackchannelLogoutDeliveryPending,
		}); err != nil {
			t.Fatalf("insert delivery: %v", err)
		}
		return id
	}
	want := insert(liveA.ClientID)
	insert(deletedA.ClientID)
	insert(liveB.ClientID)

	rows, err := deliveries.List(ctx, repository.BackchannelLogoutDeliveryListFilter{OrganizationID: &orgA, Limit: 200})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != want {
		got := make([]string, 0, len(rows))
		for _, r := range rows {
			got = append(got, r.ClientID)
		}
		t.Fatalf("organization list = %v, want only the live client of the organization (%s)", got, liveA.ClientID)
	}
}
