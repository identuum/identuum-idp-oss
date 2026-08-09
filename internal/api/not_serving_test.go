package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// stubClientRepo is a no-op repository.ClientRepository so scenario (a)
// can mount the clients surface "wired" without a database.
type stubClientRepo struct{}

func (stubClientRepo) RegisterClient(context.Context, *domain.Client) error { return nil }
func (stubClientRepo) GetClientByID(context.Context, uuid.UUID) (*domain.Client, error) {
	return nil, nil
}
func (stubClientRepo) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return nil, nil
}
func (stubClientRepo) Update(context.Context, *domain.Client) error        { return nil }
func (stubClientRepo) Delete(context.Context, uuid.UUID, *uuid.UUID) error { return nil }
func (stubClientRepo) List(context.Context, repository.Pagination, *uuid.UUID) ([]*domain.Client, int, error) {
	return nil, 0, nil
}
func (stubClientRepo) ListByServiceAccountID(context.Context, uuid.UUID, uuid.UUID) ([]*domain.Client, error) {
	return nil, nil
}
func (stubClientRepo) SaveConsent(context.Context, *domain.Consent) error { return nil }
func (stubClientRepo) GetConsent(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) (*domain.Consent, error) {
	return nil, nil
}

func nsDo(engine *gin.Engine, method, path string) (int, string, http.Header) {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

// Scenario (a): all deps wired (clients repo present) → NO fatal fault →
// the process serves normally and /health is 200 "healthy". The mounted
// NOT-SERVING guard is dormant: a normal route is not refused.
func TestNotServing_ScenarioA_ServesWhenWired(t *testing.T) {
	report := lifecycle.NewStartupReport()
	engine := NewOSSEngine(OSSRouterDeps{
		Version:       "test-vA",
		StartupReport: report,
		ClientRepo:    stubClientRepo{},
	})

	if !report.Serving() || report.HasFatal() {
		t.Fatalf("expected serving report; fatal=%v faults=%v", report.HasFatal(), report.Faults())
	}

	code, body, _ := nsDo(engine, http.MethodGet, "/health")
	if code != http.StatusOK {
		t.Fatalf("/health: status = %d, want 200; body=%s", code, body)
	}
	var h map[string]any
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("/health body not JSON: %v", err)
	}
	if h["status"] != "healthy" {
		t.Errorf("/health status = %v, want healthy; body=%s", h["status"], body)
	}

	// A normal route is reachable (not refused): the wired clients group
	// sits behind auth — 401 with no bearer, NOT 503.
	if code, _, _ := nsDo(engine, http.MethodGet, "/api/v1/clients"); code == http.StatusServiceUnavailable {
		t.Errorf("/api/v1/clients returned 503 while serving — the guard must be dormant")
	}

	if code, _, _ := nsDo(engine, http.MethodGet, "/livez"); code != http.StatusOK {
		t.Errorf("/livez status = %d, want 200", code)
	}
}

// Scenario (b): clients deps FORCED nil → RegisterClientsRoutes records a
// fatal fault instead of panicking → the process STAYS ALIVE, /health
// returns 503 "not_serving" naming the clients component, a normal
// authenticated route returns 503 (with Retry-After), and /livez stays 200.
func TestNotServing_ScenarioB_NotServingWhenClientsForcedNil(t *testing.T) {
	report := lifecycle.NewStartupReport()
	// Engine built with a report; clients absent here (mountClients
	// early-returns) so guard + health capture `report`.
	engine := NewOSSEngine(OSSRouterDeps{
		Version:       "test-vB",
		StartupReport: report,
	})

	// Force the converted reference site: both client deps nil. This MUST
	// NOT panic (P-018) — it records a fatal fault + mounts the
	// service-missing fallback. Reaching the next line proves no crash.
	handlers.RegisterClientsRoutes(engine, handlers.ClientsHandlerDeps{StartupReport: report})

	if report.Serving() {
		t.Fatalf("expected NOT-SERVING after forcing clients nil; faults=%v", report.Faults())
	}

	// /health → 503 not_serving, faults name clients-routes (secret-free).
	code, body, _ := nsDo(engine, http.MethodGet, "/health")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/health: status = %d, want 503; body=%s", code, body)
	}
	t.Logf("EVIDENCE /health (NOT-SERVING) → %d %s", code, body)
	var h struct {
		Status string            `json:"status"`
		Faults []lifecycle.Fault `json:"faults"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("/health body not JSON: %v; body=%s", err, body)
	}
	if h.Status != "not_serving" {
		t.Errorf("/health status = %q, want not_serving", h.Status)
	}
	named := false
	for _, f := range h.Faults {
		if f.Component == "clients-routes" && f.Severity == lifecycle.SeverityFatal {
			named = true
			if f.Reason == "" {
				t.Errorf("clients-routes fault has empty reason")
			}
		}
	}
	if !named {
		t.Errorf("/health faults do not name clients-routes; body=%s", body)
	}

	// A normal authenticated route is refused with 503 + Retry-After.
	code, _, hdr := nsDo(engine, http.MethodGet, "/api/v1/clients")
	if code != http.StatusServiceUnavailable {
		t.Errorf("/api/v1/clients: status = %d, want 503 (guard refuses normal traffic)", code)
	}
	if hdr.Get("Retry-After") == "" {
		t.Errorf("503 response missing Retry-After header")
	}

	// Liveness stays 200 (live, but not ready).
	code, lbody, _ := nsDo(engine, http.MethodGet, "/livez")
	if code != http.StatusOK {
		t.Errorf("/livez: status = %d, want 200; body=%s", code, lbody)
	}
}

// The converted reference site must never panic — even with NO report
// wired (nil-safe) — proving the construction-time panic is gone (P-018).
func TestRegisterClientsRoutes_BothNil_NoPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("RegisterClientsRoutes panicked with both deps nil: %v", rec)
		}
	}()
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	handlers.RegisterClientsRoutes(engine, handlers.ClientsHandlerDeps{}) // no report, both nil
}
