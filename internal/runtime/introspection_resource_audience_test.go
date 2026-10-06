package runtime

import (
	"bytes"
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// TestBuildDeps_IntrospectionAcceptsResourceAudience is OSS-INTROSPECT-AUD at
// the RUNTIME WIRING level: the introspection service the runtime builds
// answers a token minted for a live API resource to that resource (ruling h),
// while the bearer verifier it builds still refuses the same token.
//
// TEETH: drop WithResourceAudiences from buildDeps and the resource's verdict
// is inactive → this test fails.
func TestBuildDeps_IntrospectionAcceptsResourceAudience(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	kid := "introspect-aud-" + uuid.NewString()
	priv := seedActiveEdDSAKey(t, dbURL, kid)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	defer pool.Close()
	slug := "aud-" + uuid.NewString()[:8]
	orgID, resID := uuid.New(), uuid.New()
	audience := "https://" + slug + ".api.example.test"
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Aud "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_resources (id, org_id, name, audience, active, token_ttl_secs, resource_secret_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, 3600, 'x', now(), now())`, resID, orgID, "API "+slug, audience); err != nil {
		t.Fatalf("seed api resource: %v", err)
	}

	const issuer = "https://idp.introspect-aud.test"
	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    issuer,
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	deps, depsPool, _, _, _, _, _, _, _, _, _, _, err := rt.buildDeps(ctx, lifecycle.NewStartupReport())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	defer depsPool.Close()

	// No client_id: the runtime's client-liveness check would refuse a client
	// this test did not seed; that check has its own tests.
	tok := signBearer(t, priv, kid, jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": uuid.NewString(),
		"org_id": orgID.String(), "jti": uuid.NewString(), "iat": int64(1_700_000_000), "exp": int64(4_102_444_800),
	})
	caller := &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindAPIResource, ClientID: audience, AuthRecordID: resID, OrganizationID: orgID}
	resp, err := deps.IntrospectionService.IntrospectVerdictAs(ctx, tok, caller)
	if err != nil || !resp.Active {
		t.Fatalf("the API resource introspecting a token minted for it = active %v err %v; want active", resp.Active, err)
	}
	if resp, _ := deps.IntrospectionService.IntrospectVerdictAs(ctx, tok, nil); resp.Active {
		t.Errorf("the nil-caller path saw a resource-audience token as active")
	}
	if _, err := deps.TokenVerifier.VerifyBearerToken(ctx, tok); err == nil {
		t.Errorf("the IdP's bearer surface admitted a token minted for an API resource")
	}
}
