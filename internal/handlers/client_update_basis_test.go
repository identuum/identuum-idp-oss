package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// C1 (OSS v0.9.12): PUT /clients/:id decides
// what the request may do (the scope cap, whether skip_consent is being turned
// on and so needs the MFA code, which service account an unbind releases) from
// a read taken before the update locks the client row. Another save can change
// the row between that read and the lock. The update then refuses, or names
// what it really changed; it never applies a decision taken on the old row.

// basisRaceRepo is the in-memory client store with a competing save applied to
// the stored row right after read number raceAfter (1-based, counted across
// every GetClientByID). Rows are handed out as copies, as a real store does.
type basisRaceRepo struct {
	*memClientRepo
	reads     int
	raceAfter int
	race      func(stored *domain.Client)
}

func (r *basisRaceRepo) GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	r.reads++
	c, err := r.memClientRepo.GetClientByID(ctx, id)
	var out *domain.Client
	if c != nil {
		cp := *c
		out = &cp
	}
	if r.reads == r.raceAfter && r.race != nil {
		r.mu.Lock()
		r.race(r.rows[id])
		r.mu.Unlock()
	}
	return out, err
}

func (r *basisRaceRepo) Update(ctx context.Context, c *domain.Client) error {
	cp := *c
	return r.memClientRepo.Update(ctx, &cp)
}

// MutateClient reads through the racing GetClientByID above, so the update's
// own (locked) read is read 3 and sees the competing save.
func (r *basisRaceRepo) MutateClient(ctx context.Context, id uuid.UUID, _ *uuid.UUID, fn func(*domain.Client) error) (*domain.Client, *domain.Client, error) {
	return mutateClientByReadAndWrite(ctx, r, id, fn)
}

func newBasisRaceEngine(t *testing.T, prover SkipConsentProver) (skipConsentEngine, *basisRaceRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	admin := tenantAdminOf(uuid.New())
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(admin))
	repo := &basisRaceRepo{memClientRepo: newMemClientRepo()}
	rec := &audit.Recorder{}
	RegisterClientsRoutes(r, ClientsHandlerDeps{
		ClientService:      service.NewClientService(nil, repo),
		Audit:              rec,
		ClientTokenRevoker: &fakeClientTokenRevoker{},
		SkipConsentProver:  prover,
	})
	return skipConsentEngine{r: r, repo: repo.memClientRepo, rec: rec, admin: admin}, repo
}

func updatedEvents(rec *audit.Recorder, action string) []audit.Event {
	var out []audit.Event
	for _, ev := range rec.Events() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// Reads on PUT /clients/:id with a scope, skip_consent or service account in
// the body: 1 the organization check, 2 the handler's own read of the prior
// state, 3 the update's read. The competing save lands after read 2.
const raceAfterHandlerRead = 2

// RULE: CLIENT-UPDATE-AUTH-BASIS-1
func TestUpdateClient_DecisionBasisIsRecheckedUnderTheLock(t *testing.T) {
	t.Run("skip_consent turned off meanwhile is refused", basisSkipConsentChangedIsRefused)
	t.Run("scope changed meanwhile is refused", basisScopeChangedIsRefused)
	t.Run("unlink audit names the locked prior account", basisUnlinkAuditNamesLockedPriorSA)
}

func basisSkipConsentChangedIsRefused(t *testing.T) {
	p := &fakeSkipConsentProver{}
	e, repo := newBasisRaceEngine(t, p)
	id := e.seedClient(true, false)
	repo.raceAfter = raceAfterHandlerRead
	repo.race = func(stored *domain.Client) { stored.SkipConsent = false }

	// The handler read skip_consent=true, so this request is not turning it on
	// and carries no MFA code. Another admin turns it off before the lock.
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true,"name":"renamed"}`)
	if st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("= %d %v; want 400 invalid_request", st, m)
	}
	if d, _ := m["error_description"].(string); !strings.Contains(d, "changed") {
		t.Errorf("error_description %q; want a plain reason that the client changed", d)
	}
	if e.repo.rows[id].SkipConsent || e.repo.rows[id].Name != "app" {
		t.Errorf("stored skip_consent=%v name=%q; want skip_consent still off and nothing changed", e.repo.rows[id].SkipConsent, e.repo.rows[id].Name)
	}
	if n := len(updatedEvents(e.rec, "client.updated")); n != 0 || p.calls != 0 {
		t.Errorf("client.updated events=%d proof checks=%d; want none", n, p.calls)
	}
}

func basisScopeChangedIsRefused(t *testing.T) {
	e, repo := newBasisRaceEngine(t, &fakeSkipConsentProver{})
	id := e.seedClient(false, false)
	e.repo.rows[id].Scope = "openid keys:rotate"
	repo.raceAfter = raceAfterHandlerRead
	repo.race = func(stored *domain.Client) { stored.Scope = "openid" }

	// The cap let keys:rotate through only because the app already held it.
	// Another admin removes it before the lock; this save must not put it back.
	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"scope":"openid keys:rotate"}`)
	if st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("= %d %v; want 400 invalid_request", st, m)
	}
	if got := e.repo.rows[id].Scope; got != "openid" {
		t.Errorf("stored scope %q; want %q (the competing removal stands)", got, "openid")
	}
	if n := len(updatedEvents(e.rec, "client.updated")); n != 0 {
		t.Errorf("client.updated events=%d; want none", n)
	}
}

func basisUnlinkAuditNamesLockedPriorSA(t *testing.T) {
	e, repo := newBasisRaceEngine(t, &fakeSkipConsentProver{})
	id := e.seedClient(false, false)
	first, second := uuid.New(), uuid.New()
	e.repo.rows[id].ServiceAccountID = &first
	repo.raceAfter = raceAfterHandlerRead
	repo.race = func(stored *domain.Client) { stored.ServiceAccountID = &second }

	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"service_account_id":"`+uuid.Nil.String()+`"}`)
	if st != http.StatusOK {
		t.Fatalf("= %d %v; want 200", st, m)
	}
	if e.repo.rows[id].ServiceAccountID != nil {
		t.Errorf("stored service account %v; want unbound", e.repo.rows[id].ServiceAccountID)
	}
	unlinked := updatedEvents(e.rec, "service_account.unlinked_oauth_client")
	if len(unlinked) != 1 || unlinked[0].SubjectID != second {
		t.Errorf("unlink events %+v; want exactly one naming the account the update released", unlinked)
	}
}
