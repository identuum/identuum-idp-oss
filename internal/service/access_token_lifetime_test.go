package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-MUST1-RETIRE-TTL (owner rulings l and n, 2026-10-06): OSS has one
// access-token lifetime, 1 hour. A stored API resource token_ttl_secs is
// legacy and never read for issuance. With a fixed clock, client_credentials
// and authorization_code tokens get expires_in 3600 and exp - iat = 3600,
// whether the resource still carries the default 3600 or a legacy 600.

type lifetimeAudienceLookup struct{ res *domain.APIResource }

func (l lifetimeAudienceLookup) LookupAudience(_ context.Context, audience string) (*domain.APIResource, error) {
	if l.res != nil && l.res.Audience == audience {
		return l.res, nil
	}
	return nil, nil
}

func lifetimeClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	tok, _, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tok.Claims.(jwt.MapClaims)
}

func assertOneHour(t *testing.T, label string, expiresIn int64, claims jwt.MapClaims, fixed time.Time) {
	t.Helper()
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if expiresIn != 3600 {
		t.Errorf("%s: expires_in = %d, want 3600", label, expiresIn)
	}
	if int64(iat) != fixed.Unix() || int64(exp)-int64(iat) != 3600 {
		t.Errorf("%s: iat %d (want %d), exp - iat = %d, want 3600", label, int64(iat), fixed.Unix(), int64(exp)-int64(iat))
	}
}

func TestAccessTokenLifetime_OneHourWhateverTheResourceStores(t *testing.T) {
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{genEdDSAKey(t, "kid-eddsa")}}
	for _, stored := range []int{3600, 600} {
		res := &domain.APIResource{
			ID: uuid.New(), OrganizationID: uuid.New(), Name: "Billing", Audience: "https://billing.example.test",
			Active: true, TokenTTLSecs: stored,
		}

		// client_credentials: the API resource mints for its own audience.
		ts := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
			WithAudienceLookup(lifetimeAudienceLookup{res: res})
		ts.now = func() time.Time { return fixed }
		caller := &AuthenticatedClient{Kind: AuthenticatedClientKindAPIResource, ClientID: res.Audience, AuthRecordID: res.ID, OrganizationID: res.OrganizationID}
		cc, err := ts.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
			GrantType: "client_credentials", RequestedAudience: res.Audience,
		})
		if err != nil {
			t.Fatalf("stored %d: client_credentials: %v", stored, err)
		}
		ccClaims := lifetimeClaims(t, cc.AccessToken)
		if ccClaims["aud"] != res.Audience {
			t.Fatalf("stored %d: aud = %v, want the resource audience", stored, ccClaims["aud"])
		}
		assertOneHour(t, "client_credentials, resource stores "+itoaLifetime(stored), cc.ExpiresIn, ccClaims, fixed)

		// authorization_code: the user grant has no resource lookup at all;
		// even addressed to the resource audience it keeps the one hour.
		us := NewUserTokenService(nil, provider, UserTokenServiceOptions{Issuer: "https://idp.test", Audience: res.Audience})
		us.now = func() time.Time { return fixed }
		user, session := newUserAndSession(t)
		ac, err := us.IssueForConsentedClient(context.Background(), user, session, "cli-1", "openid", nil)
		if err != nil {
			t.Fatalf("stored %d: authorization_code: %v", stored, err)
		}
		assertOneHour(t, "authorization_code, resource stores "+itoaLifetime(stored), ac.ExpiresIn, lifetimeClaims(t, ac.AccessToken), fixed)
	}
}

func itoaLifetime(n int) string {
	if n == 600 {
		return "a legacy 600"
	}
	return "the default 3600"
}
