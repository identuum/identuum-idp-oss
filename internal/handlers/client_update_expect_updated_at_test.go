package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// D4: PUT /api/v1/clients/:id takes an optional expect_updated_at, the
// updated_at the admin's page showed. The save compares it with the locked row
// and refuses with 409 client_changed when another save landed in between.
// Absent means today's behaviour. The comparison is at microsecond precision,
// the precision the database stores, and PUT answers the same updated_at a
// following GET reads.

// d4Stamp is a stored updated_at as the database holds it (microseconds).
var d4Stamp = time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)

func d4Seed(e skipConsentEngine, at time.Time) uuid.UUID {
	id := e.seedClient(false, false)
	e.repo.rows[id].UpdatedAt = at
	return id
}

func d4Body(name string, expect *time.Time) string {
	if expect == nil {
		return `{"name":"` + name + `"}`
	}
	return `{"name":"` + name + `","expect_updated_at":"` + expect.Format(time.RFC3339Nano) + `"}`
}

// RULE: CLIENT-EXPECT-UPDATED-AT-1
func TestUpdateClient_ExpectUpdatedAt(t *testing.T) {
	t.Run("stale value is refused 409 and nothing is written", d4StaleIsRefused)
	t.Run("a save landing after the check read but before the lock is refused", d4ChangedBeforeTheLockIsRefused)
	t.Run("equal value saves", d4EqualSaves)
	t.Run("equal at microsecond precision saves", d4EqualAtMicrosecondSaves)
	t.Run("absent value saves as before", d4AbsentSaves)
}

func d4StaleIsRefused(t *testing.T) {
	e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
	id := d4Seed(e, d4Stamp)
	stale := d4Stamp.Add(-time.Second)
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", &stale))
	if st != http.StatusConflict || m["error"] != "client_changed" {
		t.Errorf("= %d %v; want 409 client_changed", st, m)
	}
	if msg, _ := m["message"].(string); msg == "" {
		t.Errorf("message %q; want a plain reason", msg)
	}
	if got := e.repo.rows[id]; got.Name != "app" || !got.UpdatedAt.Equal(d4Stamp) {
		t.Errorf("stored name=%q updated_at=%s; want nothing written", got.Name, got.UpdatedAt.Format(time.RFC3339Nano))
	}
	if n := len(updatedEvents(e.rec, "client.updated")); n != 0 {
		t.Errorf("client.updated events=%d; want none", n)
	}
}

func d4ChangedBeforeTheLockIsRefused(t *testing.T) {
	e, repo := newBasisRaceEngine(t, &fakeSkipConsentProver{})
	id := d4Seed(e, d4Stamp)
	later := d4Stamp.Add(time.Second)
	// A name-only PUT reads the client once (the organization check) before
	// the save's own locked read. Another save lands right after that read.
	repo.raceAfter = 1
	repo.race = func(stored *domain.Client) { stored.Name = "other"; stored.UpdatedAt = later }
	at := d4Stamp
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", &at))
	if st != http.StatusConflict || m["error"] != "client_changed" {
		t.Errorf("= %d %v; want 409 client_changed (compared under the lock, not on the handler's read)", st, m)
	}
	if got := e.repo.rows[id]; got.Name != "other" || !got.UpdatedAt.Equal(later) {
		t.Errorf("stored name=%q; want the competing save to stand", got.Name)
	}
}

func d4EqualSaves(t *testing.T) {
	e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
	id := d4Seed(e, d4Stamp)
	at := d4Stamp
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", &at))
	if st != http.StatusOK || e.repo.rows[id].Name != "renamed" {
		t.Errorf("= %d %v name=%q; want 200 renamed", st, m, e.repo.rows[id].Name)
	}
}

func d4EqualAtMicrosecondSaves(t *testing.T) {
	e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
	// An in-memory value can carry nanoseconds; the page holds what the
	// database answered, which is microseconds.
	id := d4Seed(e, d4Stamp.Add(789*time.Nanosecond))
	at := d4Stamp
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", &at))
	if st != http.StatusOK || e.repo.rows[id].Name != "renamed" {
		t.Errorf("= %d %v; want 200 (compare at microsecond precision)", st, m)
	}
}

func d4AbsentSaves(t *testing.T) {
	e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
	id := d4Seed(e, d4Stamp)
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", nil))
	if st != http.StatusOK || e.repo.rows[id].Name != "renamed" {
		t.Errorf("= %d %v; want 200 renamed", st, m)
	}
}

// microsecondClientRepo stores updated_at as PostgreSQL does (truncated to
// microseconds) and answers MutateClient with the in-memory result, as
// PgxClientRepository.MutateClient does.
type microsecondClientRepo struct{ *memClientRepo }

func (r microsecondClientRepo) Update(ctx context.Context, c *domain.Client) error {
	cp := *c
	cp.UpdatedAt = cp.UpdatedAt.Truncate(time.Microsecond)
	return r.memClientRepo.Update(ctx, &cp)
}

func (r microsecondClientRepo) MutateClient(ctx context.Context, id uuid.UUID, _ *repository.ServiceAccountLock, fn func(*domain.Client) error) (*domain.Client, *domain.Client, error) {
	return mutateClientByReadAndWrite(ctx, r, id, fn)
}

// The save's clock is pinned to a value with sub-microsecond digits, as a
// Linux wall clock has (a darwin wall clock has microsecond resolution), so
// the case is red on every host until the saved stamp is truncated.
func TestUpdateClient_AnsweredUpdatedAtEqualsTheNextRead(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	admin := tenantAdminOf(uuid.New())
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(admin))
	mem := newMemClientRepo()
	rec := &audit.Recorder{}
	clock := func() time.Time { return time.Date(2026, 10, 2, 9, 30, 0, 123456789, time.UTC) }
	RegisterClientsRoutes(r, ClientsHandlerDeps{
		ClientService:      service.NewClientService(nil, microsecondClientRepo{mem}).WithClock(clock),
		Audit:              rec,
		ClientTokenRevoker: &fakeClientTokenRevoker{},
		SkipConsentProver:  &fakeSkipConsentProver{},
	})
	e := skipConsentEngine{r: r, repo: mem, rec: rec, admin: admin}
	id := d4Seed(e, d4Stamp)
	st, put := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), d4Body("renamed", nil))
	if st != http.StatusOK {
		t.Fatalf("PUT = %d %v; want 200", st, put)
	}
	st, get := e.do(t, http.MethodGet, "/api/v1/clients/"+id.String(), "")
	if st != http.StatusOK {
		t.Fatalf("GET = %d %v; want 200", st, get)
	}
	if put["updated_at"] != get["updated_at"] {
		t.Errorf("PUT updated_at %v, next GET %v; want the same value", put["updated_at"], get["updated_at"])
	}
}
