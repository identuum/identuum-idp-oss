package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Audience-confinement MINT side (audience-confusion fix). A machine token
// with NO requested/bound audience is IdP-destined and is stamped
// aud = issuer; a token with a requested api_resource audience is RS-destined
// and keeps aud = <resource>. The verify side (admit aud=issuer, reject
// foreign/absent) is proven in internal/auth (TestVerifyBearerToken_AudienceConfinement).

const audTestIssuer = "https://idp.test"

func audClaimOf(t *testing.T, accessToken string) any {
	t.Helper()
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, err := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tok.Claims.(jwt.MapClaims)["aud"]
}

// (b) client-credentials with NO audience → aud stamped = issuer (IdP-destined).
func TestIssueClientCredentials_NoAudienceStampedIssuer(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: audTestIssuer})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got := audClaimOf(t, resp.AccessToken)
	t.Logf("EVIDENCE (b) no-audience client_credentials: aud=%v (want issuer)", got)
	if got != audTestIssuer {
		t.Fatalf("aud = %v, want %q (IdP-destined ⇒ stamp issuer)", got, audTestIssuer)
	}
}

// (c-mint) client-credentials WITH an api_resource audience → aud kept =
// resource (RS-destined, and NOT the issuer).
func TestIssueClientCredentials_WithAudienceKeptResource(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: audTestIssuer})
	const resource = "https://api.example.com"
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: resource,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got := audClaimOf(t, resp.AccessToken)
	t.Logf("EVIDENCE (c-mint) with-audience client_credentials: aud=%v (want resource, != issuer)", got)
	if got != resource {
		t.Fatalf("aud = %v, want %q (RS-destined kept)", got, resource)
	}
	if got == audTestIssuer {
		t.Fatalf("RS-destined token must NOT carry the issuer audience")
	}
}

// (d) refresh-grant with NO bound audience → aud stamped = issuer.
func TestIssueRefresh_NoBoundAudienceStampedIssuer(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: audTestIssuer}).WithRefreshTokenService(rts)
	issued, err := rts.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-1", Subject: "cli-1"}) // no Audience
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType: "refresh_token", RefreshToken: issued.Token,
	})
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}
	got := audClaimOf(t, resp.AccessToken)
	t.Logf("EVIDENCE (d) refresh no-bound-audience: aud=%v (want issuer)", got)
	if got != audTestIssuer {
		t.Fatalf("aud = %v, want %q", got, audTestIssuer)
	}
}

// (e-mint) refresh-grant WITH a bound api_resource audience → aud kept = resource.
func TestIssueRefresh_BoundAudienceKeptResource(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: audTestIssuer}).WithRefreshTokenService(rts)
	const resource = "https://api.example.com"
	issued, err := rts.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-1", Subject: "cli-1", Audience: resource})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType: "refresh_token", RefreshToken: issued.Token,
	})
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}
	got := audClaimOf(t, resp.AccessToken)
	t.Logf("EVIDENCE (e-mint) refresh bound-audience: aud=%v (want resource)", got)
	if got != resource {
		t.Fatalf("aud = %v, want %q", got, resource)
	}
}
