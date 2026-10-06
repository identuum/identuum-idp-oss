package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-INTROSPECT-AUD (owner ruling h, 2026-10-06): a token whose aud names an
// API resource (not the issuer) is active only to that API resource, and only
// when the resource and the token belong to the same organization; the client
// it was issued to keeps seeing its own token; every other caller, the
// nil-caller site path included, gets {"active":false}. The real verifier and
// the real service, deterministic times: iat and exp are fixed instants.

const (
	resIssuer   = "https://idp.test"
	resFixedIat = int64(1_700_000_000) // 2023-11-14
	resFixedExp = int64(4_102_444_800) // 2100-01-01
	resPastExp  = int64(1_000_000_000) // 2001-09-09
)

var (
	resOrgA = uuid.MustParse("0190a000-0000-7000-8000-00000000000a")
	resOrgB = uuid.MustParse("0190a000-0000-7000-8000-00000000000b")
	resA1   = &domain.APIResource{ID: uuid.MustParse("0190a000-0000-7000-8000-0000000000a1"), OrganizationID: resOrgA, Audience: "https://api.a1", Active: true}
	resA2   = &domain.APIResource{ID: uuid.MustParse("0190a000-0000-7000-8000-0000000000a2"), OrganizationID: resOrgA, Audience: "https://api.a2", Active: true}
	resB    = &domain.APIResource{ID: uuid.MustParse("0190a000-0000-7000-8000-0000000000b1"), OrganizationID: resOrgB, Audience: "https://api.b", Active: true}
	resOff  = &domain.APIResource{ID: uuid.MustParse("0190a000-0000-7000-8000-0000000000f1"), OrganizationID: resOrgA, Audience: "https://api.off", Active: false}
)

// stubResourceLookup answers like APIResourceService.LookupAudience: a
// deleted resource (or one of a deleted organization) is absent.
type stubResourceLookup struct {
	byAudience map[string]*domain.APIResource
	err        error
}

func (s stubResourceLookup) LookupAudience(_ context.Context, audience string) (*domain.APIResource, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.byAudience[audience], nil
}

type stubRevoked map[string]bool

func (s stubRevoked) IsRevoked(_ context.Context, jti string) (bool, error) { return s[jti], nil }

func resourceCaller(r *domain.APIResource) *service.AuthenticatedClient {
	return &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindAPIResource, ClientID: r.Audience, AuthRecordID: r.ID, OrganizationID: r.OrganizationID}
}

func appCaller(clientID string) *service.AuthenticatedClient {
	return &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: clientID, AuthRecordID: uuid.New(), OrganizationID: resOrgA}
}

type resourceAudienceFixture struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	kid     string
	v       *RepositoryVerifier
	svc     *service.IntrospectionService
	revoked stubRevoked
}

func newResourceAudienceFixture(t *testing.T, lookup ResourceAudienceLookup) *resourceAudienceFixture {
	t.Helper()
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-res"
	repo := &stubKeyRepo{keys: []domain.SigningKey{{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM}}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{ExpectedIssuer: resIssuer, ExpectedAudience: resIssuer}).
		WithResourceAudiences(lookup)
	revoked := stubRevoked{}
	svc := service.NewIntrospectionService(nil, v, nil).WithRevocationChecker(revoked)
	return &resourceAudienceFixture{t: t, priv: priv, kid: kid, v: v, svc: svc, revoked: revoked}
}

// token signs a client_credentials-shaped token issued to app-1 for aud.
// org == uuid.Nil leaves org_id out.
func (f *resourceAudienceFixture) token(aud any, org uuid.UUID, exp int64, jti string) string {
	f.t.Helper()
	c := jwt.MapClaims{
		"sub":        "0190a000-0000-7000-8000-0000000005a1",
		"iss":        resIssuer,
		"aud":        aud,
		"iat":        resFixedIat,
		"exp":        exp,
		"jti":        jti,
		"client_id":  "app-1",
		"actor_type": "service_account",
	}
	if org != uuid.Nil {
		c["org_id"] = org.String()
	}
	return signEdDSA(f.t, f.priv, f.kid, c)
}

func (f *resourceAudienceFixture) activeAs(raw string, caller *service.AuthenticatedClient) bool {
	f.t.Helper()
	resp, err := f.svc.IntrospectVerdictAs(context.Background(), raw, caller)
	if err != nil {
		f.t.Fatalf("IntrospectVerdictAs: unexpected store error %v", err)
	}
	if !resp.Active && (resp.Sub != "" || resp.ClientID != "" || len(resp.Aud) != 0) {
		f.t.Fatalf("an inactive answer carried claims: %+v", resp)
	}
	return resp.Active
}

func (f *resourceAudienceFixture) activeFor(raw string, caller *service.AuthenticatedClient) bool {
	f.t.Helper()
	resp, err := f.svc.IntrospectVerdictFor(context.Background(), raw, caller)
	if err != nil {
		f.t.Fatalf("IntrospectVerdictFor: unexpected store error %v", err)
	}
	return resp.Active
}

func liveLookup() stubResourceLookup {
	return stubResourceLookup{byAudience: map[string]*domain.APIResource{
		resA1.Audience: resA1, resA2.Audience: resA2, resB.Audience: resB, resOff.Audience: resOff,
	}}
}

func TestIntrospectResourceAudience_RulingH(t *testing.T) {
	f := newResourceAudienceFixture(t, liveLookup())
	tok := f.token(resA1.Audience, resOrgA, resFixedExp, "jti-a1")

	cases := []struct {
		name   string
		caller *service.AuthenticatedClient
		want   bool
	}{
		{"the named API resource, same organization", resourceCaller(resA1), true},
		{"another API resource of the same organization", resourceCaller(resA2), false},
		{"an API resource of another organization", resourceCaller(resB), false},
		{"the client the token was issued to", appCaller("app-1"), true},
		{"another app client", appCaller("app-2"), false},
		{"the nil-caller site path", nil, false},
	}
	for _, c := range cases {
		if got := f.activeAs(tok, c.caller); got != c.want {
			t.Errorf("%s: active = %v; want %v", c.name, got, c.want)
		}
	}

	// The named resource, but the token's org_id is another organization's.
	foreign := f.token(resA1.Audience, resOrgB, resFixedExp, "jti-foreign")
	if f.activeAs(foreign, resourceCaller(resA1)) {
		t.Errorf("the named resource whose organization differs from the token's org_id: active; want inactive")
	}
	// No org_id at all: the token belongs to no organization the resource is in.
	orgless := f.token(resA1.Audience, uuid.Nil, resFixedExp, "jti-orgless")
	if f.activeAs(orgless, resourceCaller(resA1)) {
		t.Errorf("a resource-audience token without org_id: active to the resource; want inactive")
	}
	// Two audiences, neither the issuer: not a token for one resource.
	multi := f.token([]any{resA1.Audience, resA2.Audience}, resOrgA, resFixedExp, "jti-multi")
	if f.activeAs(multi, resourceCaller(resA1)) || f.activeAs(multi, appCaller("app-1")) {
		t.Errorf("a token with two resource audiences: active; want inactive")
	}
}

func TestIntrospectResourceAudience_DeadResourcesAndDeadTokens(t *testing.T) {
	f := newResourceAudienceFixture(t, liveLookup())

	off := f.token(resOff.Audience, resOrgA, resFixedExp, "jti-off")
	gone := f.token("https://api.gone", resOrgA, resFixedExp, "jti-gone")
	for name, raw := range map[string]string{"an inactive resource": off, "a deleted (absent) resource": gone} {
		for _, caller := range []*service.AuthenticatedClient{resourceCaller(resOff), appCaller("app-1"), nil} {
			if f.activeAs(raw, caller) {
				t.Errorf("%s: active to %+v; want inactive", name, caller)
			}
		}
	}

	// A deleted resource's audience re-registered in another organization: a
	// token minted for orgA's resource names an audience orgB now holds.
	reregistered := f.token(resB.Audience, resOrgA, resFixedExp, "jti-rereg")
	if f.activeAs(reregistered, resourceCaller(resB)) {
		t.Errorf("a re-registered audience's new owner in another organization: active; want inactive")
	}

	revoked := f.token(resA1.Audience, resOrgA, resFixedExp, "jti-revoked")
	f.revoked["jti-revoked"] = true
	if f.activeAs(revoked, resourceCaller(resA1)) || f.activeAs(revoked, appCaller("app-1")) {
		t.Errorf("a revoked resource-audience token: active; want inactive")
	}

	expired := f.token(resA1.Audience, resOrgA, resPastExp, "jti-expired")
	if f.activeAs(expired, resourceCaller(resA1)) || f.activeAs(expired, appCaller("app-1")) {
		t.Errorf("an expired resource-audience token: active; want inactive")
	}

	// An aud naming neither the issuer nor any resource stays invalid.
	stray := f.token("https://nowhere.test", resOrgA, resFixedExp, "jti-stray")
	if _, err := f.v.IntrospectToken(context.Background(), stray); err == nil {
		t.Errorf("an aud naming neither the issuer nor a live resource: verified; want invalid")
	}
}

func TestIntrospectResourceAudience_StoreErrorIsNotAVerdict(t *testing.T) {
	f := newResourceAudienceFixture(t, stubResourceLookup{err: errors.New("db down")})
	tok := f.token(resA1.Audience, resOrgA, resFixedExp, "jti-db")
	_, err := f.svc.IntrospectVerdictAs(context.Background(), tok, resourceCaller(resA1))
	if !domain.IsAuthStoreUnavailable(err) {
		t.Fatalf("an API resource store error = %v; want the store class (503), never a verdict", err)
	}
}

func TestIntrospectResourceAudience_NeverABearerOnTheIdP(t *testing.T) {
	f := newResourceAudienceFixture(t, liveLookup())
	tok := f.token(resA1.Audience, resOrgA, resFixedExp, "jti-bearer")
	if _, err := f.v.VerifyBearerToken(context.Background(), tok); err == nil {
		t.Errorf("the IdP's own API admitted a resource-audience token as a bearer")
	}
	if _, ok, err := f.svc.IntrospectActiveClaimsVerdict(context.Background(), tok); ok || err != nil {
		t.Errorf("userinfo's verdict for a resource-audience token = ok %v err %v; want refused", ok, err)
	}
}

// Revocation (RFC 7009 §2.1) stays the issuing client's: for a
// resource-audience token neither the resource nor the nil-caller path counts.
func TestIntrospectResourceAudience_RevocationVerdict(t *testing.T) {
	f := newResourceAudienceFixture(t, liveLookup())
	tok := f.token(resA1.Audience, resOrgA, resFixedExp, "jti-rev")
	if !f.activeFor(tok, appCaller("app-1")) {
		t.Errorf("the issuing client's revocation verdict: inactive; want active")
	}
	for name, caller := range map[string]*service.AuthenticatedClient{"the resource": resourceCaller(resA1), "another app": appCaller("app-2"), "nil": nil} {
		if f.activeFor(tok, caller) {
			t.Errorf("revocation verdict for %s: active; want inactive", name)
		}
	}
}

// Issuer-audience tokens keep today's answers exactly, with the lookup wired.
func TestIntrospectResourceAudience_IssuerAudienceUnchanged(t *testing.T) {
	f := newResourceAudienceFixture(t, liveLookup())
	tok := f.token(resIssuer, resOrgA, resFixedExp, "jti-iss")
	both := f.token([]any{resIssuer, resA1.Audience}, resOrgA, resFixedExp, "jti-both")
	for _, raw := range []string{tok, both} {
		as := []struct {
			name   string
			caller *service.AuthenticatedClient
			want   bool
		}{
			{"nil caller", nil, true},
			{"an API resource", resourceCaller(resA2), true},
			{"an API resource of another organization", resourceCaller(resB), true},
			{"the issuing client", appCaller("app-1"), true},
			{"another app client", appCaller("app-2"), false},
		}
		for _, c := range as {
			if got := f.activeAs(raw, c.caller); got != c.want {
				t.Errorf("issuer-audience, IntrospectVerdictAs %s: active = %v; want %v", c.name, got, c.want)
			}
		}
		for name, c := range map[string]struct {
			caller *service.AuthenticatedClient
			want   bool
		}{"nil": {nil, true}, "issuing client": {appCaller("app-1"), true}, "another app": {appCaller("app-2"), false}} {
			if got := f.activeFor(raw, c.caller); got != c.want {
				t.Errorf("issuer-audience, IntrospectVerdictFor %s: active = %v; want %v", name, got, c.want)
			}
		}
		claims, ok, err := f.svc.IntrospectActiveClaimsVerdict(context.Background(), raw)
		if !ok || err != nil || claims.Resource != nil {
			t.Errorf("issuer-audience userinfo verdict = ok %v err %v resource %+v; want ok, no resource", ok, err, claims)
		}
	}
}
