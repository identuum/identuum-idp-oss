//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// D4 on PostgreSQL: PUT /api/v1/clients/:id with expect_updated_at, through
// the real handler, service and repository. The value a page holds is the
// updated_at a GET answered (microseconds, as the column stores it).

type d4Answer struct {
	status int
	body   map[string]any
}

func d4Engine(t *testing.T, org uuid.UUID, svc *service.ClientService) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{
		UserID: uuid.New(), OrganizationID: org, Email: "d4-admin@example.invalid",
		Role: domain.RoleOrgAdmin, Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}))
	handlers.RegisterClientsRoutes(r, handlers.ClientsHandlerDeps{ClientService: svc, Audit: &audit.Recorder{}})
	return r
}

func d4Do(r *gin.Engine, method, path, body string) d4Answer {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return d4Answer{w.Code, out}
}

func d4Put(name string, expect any) string {
	if expect == nil {
		return `{"name":"` + name + `"}`
	}
	return `{"name":"` + name + `","expect_updated_at":"` + expect.(string) + `"}`
}

func TestClientUpdateExpectUpdatedAt_Pgx(t *testing.T) {
	pool := f2ScratchPool(t)
	repo := postgres.NewPgxClientRepository(pool)
	// The save's clock carries sub-microsecond digits on every host, as a
	// Linux wall clock does, so the precision case does not depend on where
	// it runs.
	clock := func() time.Time { return time.Now().Truncate(time.Microsecond).Add(789 * time.Nanosecond) }
	setup := func(t *testing.T) (context.Context, uuid.UUID, *gin.Engine, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(cancel)
		id := f2SeedClient(t, pool, true, false)
		// The shared fixture leaves updated_at at Go's zero time; a real row
		// carries the time of its last save.
		if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET updated_at = now() WHERE id = $1`, id); err != nil {
			t.Fatal("fixture updated_at write failed")
		}
		c, err := repo.GetClientByID(ctx, id)
		if err != nil || c == nil || c.OrganizationID == nil {
			t.Fatal("fixture read failed")
		}
		r := d4Engine(t, *c.OrganizationID, service.NewClientService(nil, repo).WithClock(clock))
		got := d4Do(r, http.MethodGet, "/api/v1/clients/"+id.String(), "")
		shown, _ := got.body["updated_at"].(string)
		if got.status != http.StatusOK || shown == "" {
			t.Fatalf("GET = %d; want 200 with updated_at", got.status)
		}
		return ctx, id, r, shown
	}
	path := func(id uuid.UUID) string { return "/api/v1/clients/" + id.String() }

	t.Run("stale value is refused 409 and nothing is written", func(t *testing.T) {
		ctx, id, r, _ := setup(t)
		before, _ := repo.GetClientByID(ctx, id)
		stale := before.UpdatedAt.Add(-time.Second).Format(time.RFC3339Nano)
		got := d4Do(r, http.MethodPut, path(id), d4Put("renamed", stale))
		if got.status != http.StatusConflict || got.body["error"] != "client_changed" {
			t.Errorf("PUT = %d error=%v; want 409 client_changed", got.status, got.body["error"])
		}
		after, err := repo.GetClientByID(ctx, id)
		if err != nil || after.Name != "old" || !after.UpdatedAt.Equal(before.UpdatedAt) {
			t.Error("a refused save changed the stored client")
		}
	})

	t.Run("equal value saves", func(t *testing.T) {
		ctx, id, r, shown := setup(t)
		got := d4Do(r, http.MethodPut, path(id), d4Put("renamed", shown))
		if got.status != http.StatusOK {
			t.Errorf("PUT = %d; want 200", got.status)
		}
		if after, err := repo.GetClientByID(ctx, id); err != nil || after.Name != "renamed" {
			t.Error("an up-to-date save was not written")
		}
	})

	t.Run("absent value saves as before", func(t *testing.T) {
		ctx, id, r, _ := setup(t)
		if got := d4Do(r, http.MethodPut, path(id), d4Put("renamed", nil)); got.status != http.StatusOK {
			t.Errorf("PUT = %d; want 200", got.status)
		}
		if after, err := repo.GetClientByID(ctx, id); err != nil || after.Name != "renamed" {
			t.Error("a save without expect_updated_at was not written")
		}
	})

	t.Run("PUT answers the updated_at a following GET reads", func(t *testing.T) {
		_, id, r, _ := setup(t)
		put := d4Do(r, http.MethodPut, path(id), d4Put("renamed", nil))
		get := d4Do(r, http.MethodGet, path(id), "")
		// The same instant: GET renders the server's local offset, PUT UTC.
		p, perr := time.Parse(time.RFC3339Nano, fmt.Sprint(put.body["updated_at"]))
		g, gerr := time.Parse(time.RFC3339Nano, fmt.Sprint(get.body["updated_at"]))
		if put.status != http.StatusOK || get.status != http.StatusOK || perr != nil || gerr != nil || !p.Equal(g) {
			t.Errorf("PUT %d updated_at %v, GET %d updated_at %v; want 200, 200 and the same instant",
				put.status, put.body["updated_at"], get.status, get.body["updated_at"])
		}
	})

	t.Run("two saves from the same page: one wins, the other is refused", func(t *testing.T) {
		ctx, id, r, shown := setup(t)
		names := []string{"first", "second"}
		answers := make([]d4Answer, len(names))
		var wg sync.WaitGroup
		for i, n := range names {
			wg.Add(1)
			go func(i int, n string) {
				defer wg.Done()
				answers[i] = d4Do(r, http.MethodPut, path(id), d4Put(n, shown))
			}(i, n)
		}
		wg.Wait()
		var ok, conflict int
		winner := ""
		for i, a := range answers {
			switch {
			case a.status == http.StatusOK:
				ok++
				winner = names[i]
			case a.status == http.StatusConflict && a.body["error"] == "client_changed":
				conflict++
			}
		}
		if ok != 1 || conflict != 1 {
			t.Errorf("answers %d and %d; want exactly one 200 and one 409 client_changed", answers[0].status, answers[1].status)
		}
		if after, err := repo.GetClientByID(ctx, id); err != nil || (winner != "" && after.Name != winner) {
			t.Error("the stored name is not the winning save's")
		}
	})
}
