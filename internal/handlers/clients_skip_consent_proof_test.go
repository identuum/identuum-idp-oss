package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// D-026: turning on "skip consent" for an app needs the org_admin's current
// MFA (TOTP) code in the request, and the change is recorded with the proof.
// Turning it off, or editing an app that already skips consent, needs none.

type fakeSkipConsentProver struct {
	err      error
	calls    int
	lastCode string
}

func (f *fakeSkipConsentProver) ProveTOTP(_ context.Context, _ uuid.UUID, code string) error {
	f.calls++
	f.lastCode = code
	return f.err
}

type skipConsentEngine struct {
	r     *gin.Engine
	repo  *memClientRepo
	rec   *audit.Recorder
	admin *domain.Principal
}

func newSkipConsentEngine(t *testing.T, prover SkipConsentProver) skipConsentEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	admin := tenantAdminOf(uuid.New())
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(admin))
	repo := newMemClientRepo()
	rec := &audit.Recorder{}
	RegisterClientsRoutes(r, ClientsHandlerDeps{
		ClientService:      service.NewClientService(nil, repo),
		Audit:              rec,
		ClientTokenRevoker: &fakeClientTokenRevoker{},
		SkipConsentProver:  prover,
	})
	return skipConsentEngine{r: r, repo: repo, rec: rec, admin: admin}
}

func (e skipConsentEngine) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

const skipCreateBody = `{"name":"app","redirect_uris":["https://app.example.com/cb"],"scope":"openid"`

func (e skipConsentEngine) seedClient(skip, dynamic bool) uuid.UUID {
	id := uuid.New()
	org := e.admin.OrganizationID
	e.repo.rows[id] = &domain.Client{
		ID: id, ClientID: "cid-" + id.String()[:8], Name: "app", OrganizationID: &org,
		RedirectURIs: []string{"https://app.example.com/cb"}, Scope: "openid",
		ClientSecretHash: "hash", SkipConsent: skip, DynamicallyRegistered: dynamic,
	}
	return id
}

func TestCreateClient_SkipConsentNeedsTheAdminsMFACode(t *testing.T) {
	t.Run("no code: refused, nothing created", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true}`)
		if st != http.StatusBadRequest || m["error"] != "mfa_code_required" {
			t.Errorf("= %d %v; want 400 mfa_code_required", st, m)
		}
		if len(e.repo.rows) != 0 || p.calls != 0 {
			t.Errorf("rows=%d proofChecks=%d; want nothing created and no proof checked", len(e.repo.rows), p.calls)
		}
	})
	t.Run("wrong code: refused, nothing created", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{err: service.ErrMFAProofInvalid})
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true,"mfa_code":"000000"}`)
		if st != http.StatusForbidden || m["error"] != "invalid_mfa_code" {
			t.Errorf("= %d %v; want 403 invalid_mfa_code", st, m)
		}
		if len(e.repo.rows) != 0 {
			t.Error("a refused proof must create nothing")
		}
	})
	t.Run("admin without MFA is told to enroll", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{err: service.ErrMFANotEnrolled})
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusBadRequest || m["error"] != "mfa_not_enrolled" {
			t.Errorf("= %d %v; want 400 mfa_not_enrolled", st, m)
		}
	})
	t.Run("no prover wired: fails closed", func(t *testing.T) {
		e := newSkipConsentEngine(t, nil)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusServiceUnavailable || m["error"] != "mfa_unavailable" {
			t.Errorf("= %d %v; want 503 mfa_unavailable", st, m)
		}
		if len(e.repo.rows) != 0 {
			t.Error("nothing may be created without a proof")
		}
	})
	t.Run("a store failure is a server error, not a pass", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{err: errors.New("replay store down")})
		st, _ := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusInternalServerError || len(e.repo.rows) != 0 {
			t.Errorf("= %d rows=%d; want 500 and nothing created", st, len(e.repo.rows))
		}
	})
	t.Run("a valid code creates the app and the audit record carries the proof", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		st, _ := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`,"skip_consent":true,"mfa_code":" 123456 "}`)
		if st != http.StatusCreated || p.calls != 1 || p.lastCode != "123456" {
			t.Fatalf("= %d proofChecks=%d code=%q; want 201, one check of the trimmed code", st, p.calls, p.lastCode)
		}
		ev := e.rec.Events()
		if len(ev) != 1 || ev[0].Action != "client.created" || ev[0].Metadata["skip_consent"] != true || ev[0].Metadata["mfa_verified"] != true {
			t.Errorf("audit = %+v; want client.created with skip_consent and mfa_verified true", ev)
		}
		if _, leaked := ev[0].Metadata["mfa_code"]; leaked {
			t.Error("the code must never reach the audit record")
		}
	})
	t.Run("a public app is refused before the proof is spent", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", `{"name":"native","redirect_uris":["http://127.0.0.1/cb"],"is_public":true,"token_endpoint_auth_method":"none","skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_request" || len(e.repo.rows) != 0 || p.calls != 0 {
			t.Errorf("= %d %v rows=%d proofChecks=%d; want 400 invalid_request, nothing created, no proof spent", st, m, len(e.repo.rows), p.calls)
		}
	})
	t.Run("an app without skip_consent needs no code", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		st, _ := e.do(t, http.MethodPost, "/api/v1/clients", skipCreateBody+`}`)
		if st != http.StatusCreated || p.calls != 0 {
			t.Errorf("= %d proofChecks=%d; want 201 and no proof check", st, p.calls)
		}
	})
}

func TestUpdateClient_TurningSkipConsentOnNeedsTheAdminsMFACode(t *testing.T) {
	t.Run("on without a code: refused, unchanged", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{})
		id := e.seedClient(false, false)
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true}`)
		if st != http.StatusBadRequest || m["error"] != "mfa_code_required" || e.repo.rows[id].SkipConsent {
			t.Errorf("= %d %v skip=%v; want 400 mfa_code_required and unchanged", st, m, e.repo.rows[id].SkipConsent)
		}
	})
	t.Run("on with a wrong code: refused, unchanged", func(t *testing.T) {
		e := newSkipConsentEngine(t, &fakeSkipConsentProver{err: service.ErrMFAProofInvalid})
		id := e.seedClient(false, false)
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true,"mfa_code":"000000"}`)
		if st != http.StatusForbidden || m["error"] != "invalid_mfa_code" || e.repo.rows[id].SkipConsent {
			t.Errorf("= %d %v skip=%v; want 403 invalid_mfa_code and unchanged", st, m, e.repo.rows[id].SkipConsent)
		}
	})
	t.Run("on with a valid code: changed and recorded", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		id := e.seedClient(false, false)
		st, _ := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusOK || !e.repo.rows[id].SkipConsent || p.calls != 1 {
			t.Fatalf("= %d skip=%v proofChecks=%d; want 200, on, one check", st, e.repo.rows[id].SkipConsent, p.calls)
		}
		ev := e.rec.Events()
		if len(ev) != 1 || ev[0].Metadata["skip_consent_before"] != false || ev[0].Metadata["skip_consent_after"] != true || ev[0].Metadata["mfa_verified"] != true {
			t.Errorf("audit = %+v; want before=false after=true mfa_verified=true", ev)
		}
		if ev[0].ActorID == uuid.Nil && ev[0].ActorEmail == "" {
			t.Error("the change must name who made it")
		}
	})
	t.Run("off needs no code", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		id := e.seedClient(true, false)
		st, _ := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":false}`)
		if st != http.StatusOK || e.repo.rows[id].SkipConsent || p.calls != 0 {
			t.Errorf("= %d skip=%v proofChecks=%d; want 200, off, no check", st, e.repo.rows[id].SkipConsent, p.calls)
		}
	})
	t.Run("an app already skipping consent is edited without a code", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		id := e.seedClient(true, false)
		st, _ := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"name":"renamed","skip_consent":true}`)
		if st != http.StatusOK || !e.repo.rows[id].SkipConsent || p.calls != 0 {
			t.Errorf("= %d skip=%v proofChecks=%d; want 200, still on, no check", st, e.repo.rows[id].SkipConsent, p.calls)
		}
	})
	t.Run("a public app is refused before the proof is spent", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		id := e.seedClient(false, false)
		e.repo.rows[id].IsPublic = true
		e.repo.rows[id].ClientSecretHash = ""
		e.repo.rows[id].TokenEndpointAuthMethod = "none"
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_request" || e.repo.rows[id].SkipConsent || p.calls != 0 {
			t.Errorf("= %d %v skip=%v proofChecks=%d; want 400 invalid_request, unchanged, no proof spent", st, m, e.repo.rows[id].SkipConsent, p.calls)
		}
	})
	t.Run("an app created through dynamic registration is refused before the proof is spent", func(t *testing.T) {
		p := &fakeSkipConsentProver{}
		e := newSkipConsentEngine(t, p)
		id := e.seedClient(false, true)
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"skip_consent":true,"mfa_code":"123456"}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_request" || e.repo.rows[id].SkipConsent {
			t.Errorf("= %d %v skip=%v; want 400 invalid_request and unchanged", st, m, e.repo.rows[id].SkipConsent)
		}
		if p.calls != 0 {
			t.Error("the proof must not be spent on a request that can never succeed")
		}
	})
}
