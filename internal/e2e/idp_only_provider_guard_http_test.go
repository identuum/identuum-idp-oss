//go:build integration

// Package e2e — Q1 and Q-B3: an organization whose sign-in policy is
// idp_only always keeps an active sign-in provider.
//
//   - PUT /api/v1/organizations/:id with auth_policy idp_only answers 400
//     when the organization has no active provider (none, or only an
//     inactive one). local_only, mixed and "" are unchanged.
//   - While the policy is idp_only, DELETE of the organization's provider
//     answers 409 last_active_identity_provider and deletes nothing. Under
//     mixed DELETE keeps today's answer. An OSS organization has at most one
//     provider, so "the last active provider" is "the provider".
//   - Q-P1 (a): the provider PUT is NOT guarded. Its `active` field stays
//     ignored, so PUT active:false answers 200 and the provider stays active
//     (the silent drop is a separate item, not this guard).
//   - A policy change and a provider removal sent at the same time cannot
//     both pass: the end state is never idp_only with no active provider.
//
// The tests compose the real Gin handlers, the real services and the real
// pgx repositories against the test database. The paths are literals, so
// this file runs red against the tree before the guards.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type idpOnlyWorld struct {
	t     *testing.T
	ctx   context.Context
	repos *postgres.Repositories
	org   uuid.UUID
	e     *gin.Engine
}

func idpOnlySetup(t *testing.T) *idpOnlyWorld {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)
	w := &idpOnlyWorld{t: t, ctx: ctx, repos: repos, org: org.ID}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org.ID,
		Role:           domain.RoleOrgAdmin,
		Scope: strings.Join([]string{
			domain.ScopeOrgsRead, domain.ScopeOrgsUpdate,
			domain.ScopeIDPsCreate, domain.ScopeIDPsRead, domain.ScopeIDPsUpdate, domain.ScopeIDPsDelete,
		}, " "),
	}))
	r.PUT("/api/v1/organizations/:id", handlers.HandleUpdateOrganization(handlers.OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, repos.Organization),
		Audit:               audit.NoopService{},
	}))
	handlers.RegisterOrganizationIdentityProviderRoutes(r, handlers.OrganizationIdentityProviderHandlerDeps{
		OIDCProviderConfigService: service.NewOIDCProviderConfigService(lifecycle.NewStartupReport(), repos.IdentityProvider, e2eSigningKeyCipher()),
		Audit:                     audit.NoopService{},
		StartupReport:             lifecycle.NewStartupReport(),
	})
	w.e = r
	return w
}

func (w *idpOnlyWorld) call(method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	w.e.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (w *idpOnlyWorld) orgPath() string { return "/api/v1/organizations/" + w.org.String() }
func (w *idpOnlyWorld) idpPath() string { return w.orgPath() + "/identity-provider" }

// provider seeds the organization's oidc provider directly (fixture only).
func (w *idpOnlyWorld) provider(active bool) *domain.IdentityProvider {
	w.t.Helper()
	p, err := w.repos.IdentityProvider.Create(w.ctx, &domain.IdentityProvider{
		OrganizationID: w.org,
		Type:           domain.IDPTypeOIDC,
		Name:           "Upstream",
		Slug:           "oidc",
		Active:         active,
		Config: domain.ProviderConfig{
			IssuerURL: "https://issuer.example.invalid",
			ClientID:  "client-" + uuid.NewString()[:8],
		},
	})
	if err != nil {
		w.t.Fatalf("seed provider: %v", err)
	}
	return p
}

// setPolicy writes auth_policy directly through the repository (fixture only).
func (w *idpOnlyWorld) setPolicy(p string) {
	w.t.Helper()
	if _, err := w.repos.Organization.Update(w.ctx, w.org, repository.UpdateOrganizationOptions{AuthPolicy: &p}); err != nil {
		w.t.Fatalf("set auth_policy %q: %v", p, err)
	}
}

func (w *idpOnlyWorld) policy() string {
	w.t.Helper()
	o, err := w.repos.Organization.GetByID(w.ctx, w.org)
	if err != nil || o == nil {
		w.t.Fatalf("reload organization: %v", err)
	}
	return o.AuthPolicy
}

func (w *idpOnlyWorld) activeProviders() int {
	w.t.Helper()
	rows, err := w.repos.IdentityProvider.ListByOrganization(w.ctx, w.org)
	if err != nil {
		w.t.Fatalf("list providers: %v", err)
	}
	n := 0
	for _, p := range rows {
		if p != nil && p.Active {
			n++
		}
	}
	return n
}

// The refusal codes and plain messages (BRIEF-OSS-0913-A item 3).
const (
	errNoActiveIDP   = "no_active_identity_provider"
	msgNoActiveIDP   = "Members can only sign in with a provider. Add an active provider before you choose this sign-in policy."
	errLastActiveIDP = "last_active_identity_provider"
	msgLastActiveIDP = "Members can only sign in with a provider. Change the sign-in policy first, or add another active provider."
)

// idpOnlyErr returns the "error" and "message" fields of a JSON body.
func idpOnlyErr(body string) (string, string) {
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	e, _ := m["error"].(string)
	msg, _ := m["message"].(string)
	return e, msg
}

// providerActive reloads the organization's only provider; ok is false when
// no provider row is left.
func (w *idpOnlyWorld) providerActive() (active bool, ok bool) {
	w.t.Helper()
	rows, err := w.repos.IdentityProvider.ListByOrganization(w.ctx, w.org)
	if err != nil {
		w.t.Fatalf("list providers: %v", err)
	}
	for _, p := range rows {
		if p != nil {
			return p.Active, true
		}
	}
	return false, false
}

// validUpdateBody is a complete provider PUT (the PUT replaces the document).
func validUpdateBody(active *bool) string {
	b := map[string]any{
		"name":   "Upstream",
		"config": map[string]any{"issuer_url": "https://issuer.example.invalid", "client_id": "client-fixed"},
	}
	if active != nil {
		b["active"] = *active
	}
	out, _ := json.Marshal(b)
	return string(out)
}

// Q1: idp_only is refused while the organization has no active provider.
// The other policies are unchanged.
func TestE2E_OSS_IDPOnlyNeedsAnActiveProvider(t *testing.T) {
	t.Run("no provider", func(t *testing.T) {
		w := idpOnlySetup(t)
		before := w.policy()
		st, body := w.call(http.MethodPut, w.orgPath(), `{"auth_policy":"idp_only"}`)
		if st != http.StatusBadRequest {
			t.Fatalf("PUT idp_only with no provider = %d %s; want 400 %s", st, body, errNoActiveIDP)
		}
		if e, msg := idpOnlyErr(body); e != errNoActiveIDP || msg != msgNoActiveIDP {
			t.Errorf("refusal body error=%q message=%q; want %q with the plain message", e, msg, errNoActiveIDP)
		}
		if got := w.policy(); got != before {
			t.Errorf("auth_policy after the refusal = %q; want %q (nothing written)", got, before)
		}
	})
	t.Run("only an inactive provider", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(false)
		before := w.policy()
		st, body := w.call(http.MethodPut, w.orgPath(), `{"auth_policy":"idp_only"}`)
		if st != http.StatusBadRequest {
			t.Fatalf("PUT idp_only with only an inactive provider = %d %s; want 400 %s", st, body, errNoActiveIDP)
		}
		if e, msg := idpOnlyErr(body); e != errNoActiveIDP || msg != msgNoActiveIDP {
			t.Errorf("refusal body error=%q message=%q; want %q with the plain message", e, msg, errNoActiveIDP)
		}
		if got := w.policy(); got != before {
			t.Errorf("auth_policy after the refusal = %q; want %q (nothing written)", got, before)
		}
	})
	// Controls: green today and after the guard.
	t.Run("control: an active provider", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(true)
		if st, body := w.call(http.MethodPut, w.orgPath(), `{"auth_policy":"idp_only"}`); st != http.StatusOK {
			t.Fatalf("PUT idp_only with an active provider = %d %s; want 200", st, body)
		}
	})
	for _, p := range []string{"local_only", "mixed", ""} {
		t.Run("control: "+p+" with no provider", func(t *testing.T) {
			w := idpOnlySetup(t)
			if st, body := w.call(http.MethodPut, w.orgPath(), `{"auth_policy":"`+p+`"}`); st != http.StatusOK {
				t.Fatalf("PUT %q with no provider = %d %s; want 200", p, st, body)
			}
		})
	}
}

// Q-B3 as narrowed by Q-P1 (a): under idp_only the provider is not deleted;
// under mixed DELETE keeps today's answer. The provider PUT is not guarded:
// `active` stays ignored, so PUT active:false answers 200 and the provider
// stays active. An OSS organization has at most one provider, so there is no
// "non-last provider" case.
func TestE2E_OSS_IDPOnlyKeepsItsLastActiveProvider(t *testing.T) {
	off := false
	t.Run("delete the last active provider", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(true)
		w.setPolicy(domain.AuthPolicyIDPOnly)
		st, body := w.call(http.MethodDelete, w.idpPath(), "")
		if st != http.StatusConflict {
			t.Fatalf("DELETE the last active provider under idp_only = %d %s; want 409 %s", st, body, errLastActiveIDP)
		}
		if e, msg := idpOnlyErr(body); e != errLastActiveIDP || msg != msgLastActiveIDP {
			t.Errorf("refusal body error=%q message=%q; want %q with the plain message", e, msg, errLastActiveIDP)
		}
		if active, ok := w.providerActive(); !ok || !active {
			t.Errorf("provider after the refusal: present=%v active=%v; want present and active (nothing deleted)", ok, active)
		}
	})
	// Q-P1 (a): OSS has no disable path; the PUT keeps today's answer.
	t.Run("control: PUT active=false under idp_only is not a disable path", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(true)
		w.setPolicy(domain.AuthPolicyIDPOnly)
		if st, body := w.call(http.MethodPut, w.idpPath(), validUpdateBody(&off)); st != http.StatusOK {
			t.Fatalf("PUT active=false under idp_only = %d %s; want 200 (Q-P1 (a): active stays ignored)", st, body)
		}
		if active, ok := w.providerActive(); !ok || !active {
			t.Errorf("provider after PUT active=false: present=%v active=%v; want present and active", ok, active)
		}
		if got := w.policy(); got != domain.AuthPolicyIDPOnly {
			t.Errorf("auth_policy after the PUT = %q; want %q", got, domain.AuthPolicyIDPOnly)
		}
	})
	// Control: today's answer under mixed.
	t.Run("control: delete under mixed", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(true)
		w.setPolicy(domain.AuthPolicyMixed)
		if st, body := w.call(http.MethodDelete, w.idpPath(), ""); st != http.StatusOK {
			t.Fatalf("DELETE under mixed = %d %s; want 200", st, body)
		}
		if _, ok := w.providerActive(); ok {
			t.Errorf("provider still present after DELETE under mixed; want it deleted")
		}
	})
	t.Run("control: an edit that keeps it active under idp_only", func(t *testing.T) {
		w := idpOnlySetup(t)
		w.provider(true)
		w.setPolicy(domain.AuthPolicyIDPOnly)
		if st, body := w.call(http.MethodPut, w.idpPath(), validUpdateBody(nil)); st != http.StatusOK {
			t.Fatalf("PUT without active under idp_only = %d %s; want 200", st, body)
		}
	})
}

// The policy change and the provider removal serialize: whichever lands
// second sees the first, so the organization never ends idp_only with no
// active provider.
func TestE2E_OSS_IDPOnlyPolicyAndProviderRemovalSerialize(t *testing.T) {
	w := idpOnlySetup(t)
	for round := 0; round < 10; round++ {
		w.setPolicy(domain.AuthPolicyMixed)
		if w.activeProviders() == 0 {
			w.provider(true)
		}
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			st, _ := w.call(http.MethodPut, w.orgPath(), `{"auth_policy":"idp_only"}`)
			codes <- st
		}()
		go func() {
			defer wg.Done()
			st, _ := w.call(http.MethodDelete, w.idpPath(), "")
			codes <- st
		}()
		wg.Wait()
		close(codes)
		for st := range codes {
			switch st {
			case http.StatusOK, http.StatusBadRequest, http.StatusConflict:
			default:
				t.Fatalf("round %d: a request answered %d; want 200, 400 or 409", round, st)
			}
		}
		if w.policy() == domain.AuthPolicyIDPOnly && w.activeProviders() == 0 {
			t.Fatalf("round %d: the organization is idp_only with no active provider", round)
		}
	}
}
