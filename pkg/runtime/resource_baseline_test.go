package runtime_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// resourceRig is a runtime on its own migrated scratch database with two
// organizations, an API resource in each, and a signed token per actor.
type resourceRig struct {
	dsn, addr                string
	db                       *sql.DB
	orgA, resA, resB         string
	adminA, userA, siteAdmin string
}

// seedResourceRig migrates a scratch database and seeds it; startResourceRig
// then serves it with opts.
func seedResourceRig(t *testing.T, name string) *resourceRig {
	t.Helper()
	dsn, db := scratchDatabase(t, "identuum_idp_oss_test_seam4_"+name)
	if _, err := postgres.RunMigrations(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", testEncryptionKey)
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	kid, priv := seedSigningKey(t, dsn)
	pool, err := postgres.NewPool(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, nil)
	ctx := context.Background()
	rig := &resourceRig{dsn: dsn, db: db}
	var orgs [2]uuid.UUID
	var res [2]string
	for i, slug := range []string{"seam4a", "seam4b"} {
		now := time.Now().UTC()
		o, err := repos.Organization.Create(ctx, &domain.Organization{Name: slug, Domain: slug + ".test", OrgSlug: slug,
			Active: true, MaxSessionsPerUser: 10, MFAPolicy: "optional", CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("seed organization: %v", err)
		}
		orgs[i] = o.ID
		r := &domain.APIResource{ID: uuid.New(), OrganizationID: o.ID, Name: slug + "-api", Audience: "https://" + slug + ".api.test",
			Active: true, TokenTTLSecs: 3600, ResourceSecretHash: "seeded", CreatedAt: now, UpdatedAt: now}
		if err := repos.APIResource.Create(ctx, r, nil); err != nil {
			t.Fatalf("seed API resource: %v", err)
		}
		res[i] = r.ID.String()
	}
	rig.orgA, rig.resA, rig.resB = orgs[0].String(), res[0], res[1]
	token := func(role string, org uuid.UUID) string {
		// An org_admin role holds authority only with an org-admin scope.
		scope := "openid " + strings.Join(domain.OrgAdminSessionScopes, " ")
		return signToken(t, kid, priv, jwt.MapClaims{
			"iss": "http://localhost:7113", "aud": "http://localhost:7113", "sub": uuid.NewString(),
			"org_id": org.String(), "role": role, "actor_type": "user", "scope": scope,
			"jti": uuid.NewString(), "exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
	}
	rig.adminA, rig.userA, rig.siteAdmin = token("org_admin", orgs[0]), token("org_user", orgs[0]), token("site_admin", uuid.MustParse(domain.SystemOrgID))
	return rig
}

func startResourceRig(t *testing.T, rig *resourceRig, opts runtime.Options) {
	t.Helper()
	ln := listen(t)
	opts.Issuer, opts.DatabaseURL, opts.DataDir, opts.Stdout, opts.Stderr = "http://localhost:7113", rig.dsn, t.TempDir(), io.Discard, io.Discard
	rt, err := runtime.NewWithListener(opts, ln)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(t, rt) })
	rig.addr = ln.Addr().String()
}

// do sends one API resource request.
func (r *resourceRig) do(t *testing.T, method, path, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+r.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// masked replaces every value that differs between runs by construction
// (ids, timestamps, the generated secret) with its key.
func masked(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch k {
			case "id", "resource_id", "organization_id", "created_at", "updated_at", "resource_secret", "deleted", "correlation_id":
				x[k] = "<" + k + ">"
			default:
				x[k] = masked(val)
			}
		}
	case []any:
		for i := range x {
			x[i] = masked(x[i])
		}
	}
	return v
}

// OSS-SEAM-4 proof 6: with no restrictions, API resource create, update and
// delete answer as they did at 221b2fa. The test compiles at that commit
// too; run there and here, the transcript digests must be equal. A
// transcript is, per request, the status, every header but Date,
// Content-Length and X-Request-Id, and the JSON body with run-varying values
// masked.
func TestAPIResourceWrites_TranscriptWithoutRestrictions(t *testing.T) {
	rig := seedResourceRig(t, "baseline")
	startResourceRig(t, rig, runtime.Options{})
	corpus := []struct {
		name, method, path, token, body string
		status                          int
	}{
		{"create", http.MethodPost, "/api/v1/api-resources", rig.adminA, `{"name":"made","audience":"https://made.api.test"}`, 201},
		{"update", http.MethodPut, "/api/v1/api-resources/" + rig.resA, rig.adminA, `{"name":"renamed","active":false}`, 200},
		{"delete", http.MethodDelete, "/api/v1/api-resources/" + rig.resA, rig.adminA, "", 200},
		{"create invalid", http.MethodPost, "/api/v1/api-resources", rig.adminA, `{"name":"","audience":""}`, 400},
		{"update another tenant's", http.MethodPut, "/api/v1/api-resources/" + rig.resB, rig.adminA, `{"name":"x"}`, 404},
		{"delete another tenant's", http.MethodDelete, "/api/v1/api-resources/" + rig.resB, rig.adminA, "", 200},
		{"site_admin create", http.MethodPost, "/api/v1/api-resources", rig.siteAdmin, `{"name":"s","audience":"https://s.api.test"}`, 403},
		{"org_user create", http.MethodPost, "/api/v1/api-resources", rig.userA, `{"name":"u","audience":"https://u.api.test"}`, 403},
	}
	var transcript strings.Builder
	for _, c := range corpus {
		resp := rig.do(t, c.method, c.path, c.token, c.body)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s: answered %d; want %d", c.name, resp.StatusCode, c.status)
		}
		var names []string
		for k := range resp.Header {
			if k != "Date" && k != "Content-Length" && k != "X-Request-Id" {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		fmt.Fprintf(&transcript, "%s %d\n", c.name, resp.StatusCode)
		for _, k := range names {
			fmt.Fprintf(&transcript, "  %s: %s\n", k, strings.Join(resp.Header[k], ", "))
		}
		var body any
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("%s: the answer is not JSON", c.name)
		}
		out, _ := json.Marshal(masked(body))
		fmt.Fprintf(&transcript, "  %s\n", out)
	}
	t.Logf("api-resource transcript sha256=%x (%d bytes)", sha256.Sum256([]byte(transcript.String())), transcript.Len())
}
