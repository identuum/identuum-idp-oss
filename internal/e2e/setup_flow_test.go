//go:build integration

// End-to-end integration spec for the appliance setup foundation.
//
// Prerequisites: same as oss_e2e_test.go — set
// IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) to a
// Postgres connection string. The test applies OSS migrations and resets
// the system_setup_state row before each flow.
//
// Safety: no raw tokens, hashes, signing-key material, or DB URLs leak
// into assertion messages.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// resetSetupFlowState wipes the system_setup_state row back to
// setup_required AND tears down any artefacts the prior test may have
// created (organisations, site_admin row, signing keys) so the e2e flow
// always starts from a clean fresh-install posture.
func resetSetupFlowState(t *testing.T, ctx context.Context, pool postgres.DBTX) {
	t.Helper()
	resets := []string{
		`DELETE FROM signing_keys`,
		// Fresh-install posture requires ZERO users — including the sentinel
		// site_admin, which the model teeth (migrations 0027/0028) make
		// undeletable by DML on purpose: "the site_admin cannot be deleted
		// (AdminPermissionsModel.md)". Other suites sharing this database
		// (internal/postgres Rg1/Rg2) legitimately seed that sentinel, so the
		// DELETE statements that used to stand here tripped the guard and
		// failed the whole flow (OSS-SETUPFLOW-RESET-VS-TEETH).
		//
		// TRUNCATE is the documented test-only escape, not a hole: PostgreSQL
		// does not fire row-level DELETE triggers on TRUNCATE, and TRUNCATE
		// requires table ownership — a strictly higher privilege than the
		// stray DML (support scripts, psql sessions, restores) the teeth
		// exist to stop. The guard itself is untouched; this helper simulates
		// the one state the model cannot forbid: a database on which setup
		// has never run. CASCADE reaps the FK children (sessions, tokens),
		// which the old per-row DELETEs reached via ON DELETE CASCADE anyway.
		`TRUNCATE users CASCADE`,
		`DELETE FROM organizations WHERE id != '00000000-0000-7000-0000-000000000000'`,
		`UPDATE system_setup_state
		    SET status = 'setup_required',
		        setup_token_hash = NULL,
		        setup_token_created_at = NULL,
		        completed_at = NULL,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = '00000000-0000-7000-0000-000000000010'`,
	}
	for _, q := range resets {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("reset (q=%q): %v", q, err)
		}
	}
}

// TestE2E_OSS_SetupFlow exercises the appliance setup foundation
// against a real Postgres + the real gin engine. Each subtest builds
// on the prior; the test does NOT use t.Parallel so the database state
// transitions are deterministic.
func TestE2E_OSS_SetupFlow(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	resetSetupFlowState(t, ctx, pool)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.Organization == nil || repos.Key == nil {
		t.Fatalf("repository factory returned nil core repos")
	}
	setupRepo := postgres.NewPgxSetupStateRepository(pool)
	orgSvc := service.NewOrganizationService(nil, repos.Organization)
	keySvc := service.NewKeyService(repos.Key)

	dataDir := t.TempDir()
	setupSvc := setup.New(setup.Deps{
		Repo:            setupRepo,
		OrgService:      orgSvc,
		KeyService:      keySvc,
		OrgRepo:         repos.Organization,
		UserRepo:        repos.User,
		Issuer:          "http://localhost:7113",
		UIPublicBaseURL: "http://localhost:7104",
	})

	banner, err := setupSvc.Initialize(ctx, dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if banner == nil {
		t.Fatalf("expected non-nil banner on fresh DB")
	}

	engine := api.NewOSSEngine(api.OSSRouterDeps{
		Version:      "e2e-test",
		SetupService: setupSvc,
		SetupDataDir: dataDir,
		DiscoveryConfig: server.OIDCDiscoveryConfig{
			Issuer: "http://localhost:7113",
		},
	})
	ts := httptest.NewServer(engine)
	t.Cleanup(ts.Close)

	// --- status: setup_required ------------------------------------------------
	t.Run("status_setup_required", func(t *testing.T) {
		body := mustGetJSON(t, ts.URL+"/api/setup/status")
		if got, _ := body["state"].(string); got != domain.SetupStatusRequired {
			t.Fatalf("state = %v; want %s", body["state"], domain.SetupStatusRequired)
		}
		if got, _ := body["setup_complete"].(bool); got {
			t.Fatalf("setup_complete should be false on fresh DB")
		}
		if got, _ := body["product"].(string); got != setup.ProductOSS {
			t.Fatalf("product = %v; want %s", body["product"], setup.ProductOSS)
		}
		// No secrets in the body.
		for _, banned := range []string{"setup_token", "setup_token_hash", "password", "private_key"} {
			if _, present := body[banned]; present {
				t.Errorf("status body must not contain %q field", banned)
			}
		}
	})

	// --- verify-token: bad token = 401 ----------------------------------------
	t.Run("verify_token_bad_401", func(t *testing.T) {
		code, _ := mustPostJSON(t, ts.URL+"/api/setup/verify-token",
			map[string]string{"setup_token": "WRONG"})
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d; want 401", code)
		}
	})

	// --- verify-token: good = 204 ---------------------------------------------
	t.Run("verify_token_good_204", func(t *testing.T) {
		code, _ := mustPostJSON(t, ts.URL+"/api/setup/verify-token",
			map[string]string{"setup_token": banner.SetupToken})
		if code != http.StatusNoContent {
			t.Errorf("status = %d; want 204", code)
		}
	})

	// --- complete: bad token = 401 --------------------------------------------
	t.Run("complete_bad_token_401", func(t *testing.T) {
		code, _ := mustPostJSON(t, ts.URL+"/api/setup/complete", map[string]string{
			"setup_token":         "WRONG",
			"organization_name":   "Acme Corp",
			"organization_domain": "acme.example",
			"admin_email":         "owner@acme.example",
			"admin_password":      "Very-Long-Test-Password-1234!",
		})
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d; want 401", code)
		}
		// State must NOT have changed.
		body := mustGetJSON(t, ts.URL+"/api/setup/status")
		if body["state"] != domain.SetupStatusRequired {
			t.Errorf("state changed to %v after bad-token complete attempt", body["state"])
		}
	})

	// --- complete: happy path -------------------------------------------------
	t.Run("complete_happy_path", func(t *testing.T) {
		code, body := mustPostJSON(t, ts.URL+"/api/setup/complete", map[string]string{
			"setup_token":         banner.SetupToken,
			"organization_name":   "Acme Corp",
			"organization_domain": "acme.example",
			"admin_email":         "owner@acme.example",
			"admin_password":      "Very-Long-Test-Password-1234!",
		})
		if code != http.StatusOK {
			t.Fatalf("status = %d; want 200", code)
		}
		if got, _ := body["state"].(string); got != domain.SetupStatusComplete {
			t.Errorf("state = %v; want %s", body["state"], domain.SetupStatusComplete)
		}
		if got, _ := body["organization_name"].(string); got != "Acme Corp" {
			t.Errorf("organization_name = %v", body["organization_name"])
		}
		if got, _ := body["admin_email"].(string); got != "owner@acme.example" {
			t.Errorf("admin_email = %v", body["admin_email"])
		}
	})

	// --- DB state after complete ----------------------------------------------
	t.Run("db_state_after_complete", func(t *testing.T) {
		systemOrgID, _ := uuid.Parse(domain.SystemOrgID)

		// signing key: exactly one active EdDSA.
		keys, err := repos.Key.GetActiveSigningKeys(ctx)
		if err != nil {
			t.Fatalf("get active keys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("active keys = %d; want 1", len(keys))
		}
		if keys[0].Algorithm != domain.KeyAlgorithmEdDSA {
			t.Errorf("algorithm = %v; want EdDSA", keys[0].Algorithm)
		}

		// site_admin pinned at SiteAdminID.
		siteAdminID, _ := uuid.Parse(domain.SiteAdminID)
		u, err := repos.User.GetByID(ctx, siteAdminID)
		if err != nil {
			t.Fatalf("get site_admin by ID: %v", err)
		}
		if u.Role != domain.RoleSiteAdmin {
			t.Errorf("role = %v; want site_admin", u.Role)
		}
		if u.OrganizationID != systemOrgID {
			t.Errorf("org = %v; want system org", u.OrganizationID)
		}
		// R6/R7 (G15, be4ff0b): the LOGIN identity is pinned to the canonical
		// address and the operator's address goes to contact_email. This
		// assertion used to expect the operator address as the login — the old
		// pre-model behaviour — and stayed unnoticed because the reset above
		// it failed first and masked everything downstream.
		if u.Email != domain.SiteAdminEmail {
			t.Errorf("email = %q; want %s (the model pins the login identity; "+
				"the operator address belongs in contact_email)", u.Email, domain.SiteAdminEmail)
		}
		// Read contact_email STRAIGHT FROM THE ROW: GetByID's SELECT does not
		// project the column (its scanUser list predates R7's writer), so
		// u.ContactEmail is always "" through that reader and asserting on it
		// would measure the projection, not the data.
		var contactEmail string
		if err := pool.QueryRow(ctx,
			`SELECT COALESCE(contact_email, '') FROM users WHERE id = $1`, siteAdminID).
			Scan(&contactEmail); err != nil {
			t.Fatalf("read contact_email: %v", err)
		}
		if contactEmail != "owner@acme.example" {
			t.Errorf("contact_email = %q; want owner@acme.example (R7: the separate "+
				"contact field carries the operator's address)", contactEmail)
		}

		// First non-system organisation exists.
		orgs, _, err := repos.Organization.List(ctx, repository.OrganizationFilter{}, repository.NewPagination(1, 10), repository.Sort{})
		if err != nil {
			t.Fatalf("list orgs: %v", err)
		}
		nonSystem := 0
		for _, o := range orgs {
			if o.ID != systemOrgID {
				nonSystem++
			}
		}
		if nonSystem != 1 {
			t.Errorf("non-system org count = %d; want 1", nonSystem)
		}
	})

	// --- status: setup_complete -----------------------------------------------
	t.Run("status_setup_complete", func(t *testing.T) {
		body := mustGetJSON(t, ts.URL+"/api/setup/status")
		if got, _ := body["state"].(string); got != domain.SetupStatusComplete {
			t.Fatalf("state = %v; want %s", body["state"], domain.SetupStatusComplete)
		}
		if got, _ := body["setup_complete"].(bool); !got {
			t.Errorf("setup_complete should be true")
		}
		if got, _ := body["first_signing_key_exists"].(bool); !got {
			t.Errorf("first_signing_key_exists should be true")
		}
		if got, _ := body["site_admin_exists"].(bool); !got {
			t.Errorf("site_admin_exists should be true")
		}
		if got, _ := body["first_organization_exists"].(bool); !got {
			t.Errorf("first_organization_exists should be true")
		}
	})

	// --- replay: complete again = 410 -----------------------------------------
	t.Run("complete_replay_410", func(t *testing.T) {
		code, _ := mustPostJSON(t, ts.URL+"/api/setup/complete", map[string]string{
			"setup_token":         banner.SetupToken,
			"organization_name":   "Acme Corp",
			"organization_domain": "acme.example",
			"admin_email":         "owner@acme.example",
			"admin_password":      "Very-Long-Test-Password-1234!",
		})
		if code != http.StatusGone {
			t.Errorf("status = %d; want 410 on replay", code)
		}
	})

	// --- replay: verify-token after complete = 410 ----------------------------
	t.Run("verify_token_after_complete_410", func(t *testing.T) {
		code, _ := mustPostJSON(t, ts.URL+"/api/setup/verify-token",
			map[string]string{"setup_token": banner.SetupToken})
		if code != http.StatusGone {
			t.Errorf("status = %d; want 410", code)
		}
	})

	// --- token file is gone ---------------------------------------------------
	t.Run("token_file_gone", func(t *testing.T) {
		if _, err := setup.ReadTokenFile(dataDir); err == nil {
			t.Errorf("token file should be deleted after Complete; data dir=%s", dataDir)
		}
	})
}

// mustPostJSON posts the supplied body as application/json and returns
// (status, body). Failures fatal-stop the surrounding subtest. The body
// is parsed as JSON when present; an empty body returns an empty map.
func mustPostJSON(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &out)
	}
	return resp.StatusCode, out
}

// Avoid "declared and not used" on time import if we later add a deadline.
var _ = time.Now
