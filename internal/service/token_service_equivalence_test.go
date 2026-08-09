package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// A-4 Phase 2 equivalence teeth: prove IssueClientCredentials (non-SA + SA)
// and IssueRefresh, rewired through the AccessTokenMinter seam, produce
// BYTE-IDENTICAL wire tokens to the pre-A-4 inline claim map for the same
// inputs+key (EdDSA signing is deterministic, so equality is exact), and
// each verifies under the key.

const (
	equivIssuer = "https://idp.test"
	equivJTI    = "0192cccc-dddd-7eee-8fff-000000000000"
)

func equivFixedNow() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }

// edTokenSvcFixture builds a TokenService with a pinned clock+jti backed by a
// single fixed EdDSA key; returns the raw ed25519 keys + kid so the test can
// reconstruct the expected token independently.
func edTokenSvcFixture(t *testing.T) (*TokenService, ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	kid := "kid-eddsa-equiv2"
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: equivIssuer})
	svc.now = equivFixedNow
	svc.newJTI = func() (string, error) { return equivJTI, nil }
	return svc, priv, pub, kid
}

// signGolden reproduces the pre-A-4 inline signing path: EdDSA over the exact
// claim map, with the kid header — the golden the seam must match byte-for-byte.
func signGolden(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("golden sign: %v", err)
	}
	return signed
}

// verifyGolden parses+verifies under pub with the parser clock pinned to the
// fixed issuance time (so the deliberately-fixed exp is not treated expired).
func verifyGolden(t *testing.T, token string, pub ed25519.PublicKey, kid string) {
	t.Helper()
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(equivFixedNow),
	).Parse(token, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("verify: err=%v valid=%v", err, tok.Valid)
	}
	if tok.Header["kid"] != kid {
		t.Errorf("kid = %v, want %q", tok.Header["kid"], kid)
	}
}

// TestIssueClientCredentials_Equivalence_NonSA: sub == client_id, no
// actor_type, aud falls back to issuer, no scope requested.
func TestIssueClientCredentials_Equivalence_NonSA(t *testing.T) {
	svc, priv, pub, kid := edTokenSvcFixture(t)
	exp := equivFixedNow().Add(time.Hour)

	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("IssueClientCredentials: %v", err)
	}

	golden := signGolden(t, priv, kid, jwt.MapClaims{
		"iss":       equivIssuer,
		"sub":       "cli-1",
		"client_id": "cli-1",
		"iat":       equivFixedNow().Unix(),
		"exp":       exp.Unix(),
		"jti":       equivJTI,
		"aud":       equivIssuer, // issuer fallback (no requested audience)
	})
	if resp.AccessToken != golden {
		t.Fatalf("non-SA cc token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.AccessToken, golden)
	}
	verifyGolden(t, resp.AccessToken, pub, kid)
}

// TestIssueClientCredentials_Equivalence_SABound: sub == SA UUID, client_id
// preserved, actor_type + org_id + role stamped from the SA subject.
func TestIssueClientCredentials_Equivalence_SABound(t *testing.T) {
	svc, priv, pub, kid := edTokenSvcFixture(t)
	exp := equivFixedNow().Add(time.Hour)

	saID := uuid.New()
	orgID := uuid.New()
	saLookup := &stubServiceAccountLookup{want: &ServiceAccountTokenSubject{
		Subject:        saID.String(),
		OrganizationID: orgID,
		Role:           "org_admin",
		ActorType:      ActorTypeServiceAccount,
	}}
	clientLookup := &stubClientLookup{client: &domain.Client{ClientID: "cli-1", ServiceAccountID: &saID}}
	svc = svc.WithServiceAccountLookup(saLookup, clientLookup)

	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("IssueClientCredentials(SA): %v", err)
	}

	golden := signGolden(t, priv, kid, jwt.MapClaims{
		"iss":        equivIssuer,
		"sub":        saID.String(),
		"client_id":  "cli-1",
		"iat":        equivFixedNow().Unix(),
		"exp":        exp.Unix(),
		"jti":        equivJTI,
		"actor_type": ActorTypeServiceAccount,
		"org_id":     orgID.String(),
		"role":       "org_admin",
		"aud":        equivIssuer,
	})
	if resp.AccessToken != golden {
		t.Fatalf("SA-bound cc token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.AccessToken, golden)
	}
	verifyGolden(t, resp.AccessToken, pub, kid)
}

// TestIssueRefresh_Equivalence: sub/client_id/scope from the consumed record,
// aud falls back to issuer (no bound audience).
func TestIssueRefresh_Equivalence(t *testing.T) {
	svc, priv, pub, kid := edTokenSvcFixture(t)
	exp := equivFixedNow().Add(time.Hour)

	repo := newInMemoryRefreshTokenRepo()
	rts := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	svc = svc.WithRefreshTokenService(rts)
	issued, err := rts.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1", Scope: "read",
	})
	if err != nil {
		t.Fatalf("seed refresh: %v", err)
	}

	resp, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: issued.Token,
	})
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	if resp.RefreshToken == "" || resp.RefreshToken == issued.Token {
		t.Fatalf("rotation failed: %q vs %q", resp.RefreshToken, issued.Token)
	}

	golden := signGolden(t, priv, kid, jwt.MapClaims{
		"iss":       equivIssuer,
		"sub":       "cli-1",
		"client_id": "cli-1",
		"iat":       equivFixedNow().Unix(),
		"exp":       exp.Unix(),
		"jti":       equivJTI,
		"scope":     "read",
		"aud":       equivIssuer,
	})
	if resp.AccessToken != golden {
		t.Fatalf("refresh access token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.AccessToken, golden)
	}
	verifyGolden(t, resp.AccessToken, pub, kid)
}

// clientIDDroppingMinter wraps the real JWT minter but blanks ClientID so the
// minted token omits the client_id claim — a stand-in for a regressed minter.
type clientIDDroppingMinter struct{ inner oidc.AccessTokenMinter }

func (m clientIDDroppingMinter) Mint(ctx context.Context, tc oidc.TokenClaims) (string, string, error) {
	tc.ClientID = ""
	return m.inner.Mint(ctx, tc)
}

// TestTokenService_Equivalence_DroppedClaimBreaksIt is the revert-proof: a
// minter that drops the client_id claim produces a token that is NOT
// byte-identical to the golden for EACH grant (non-SA cc, SA cc, refresh) —
// so every equivalence assertion above would fail. This proves the seam is
// load-bearing, not a hollow relabel.
func TestTokenService_Equivalence_DroppedClaimBreaksIt(t *testing.T) {
	exp := equivFixedNow().Add(time.Hour)

	t.Run("client_credentials", func(t *testing.T) {
		svc, priv, _, kid := edTokenSvcFixture(t)
		svc.minter = clientIDDroppingMinter{inner: newJWTAccessTokenMinter(svc.keys)}
		resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
			GrantType: "client_credentials",
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		golden := signGolden(t, priv, kid, jwt.MapClaims{
			"iss": equivIssuer, "sub": "cli-1", "client_id": "cli-1",
			"iat": equivFixedNow().Unix(), "exp": exp.Unix(), "jti": equivJTI, "aud": equivIssuer,
		})
		if resp.AccessToken == golden {
			t.Fatalf("dropped-claim minter still matched the golden — equivalence test not load-bearing")
		}
		tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.AccessToken, jwt.MapClaims{})
		if _, present := tok.Claims.(jwt.MapClaims)["client_id"]; present {
			t.Errorf("client_id should be absent under the dropping minter")
		}
	})

	t.Run("refresh_token", func(t *testing.T) {
		svc, priv, _, kid := edTokenSvcFixture(t)
		rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
		svc = svc.WithRefreshTokenService(rts)
		svc.minter = clientIDDroppingMinter{inner: newJWTAccessTokenMinter(svc.keys)}
		issued, _ := rts.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-1", Subject: "cli-1", Scope: "read"})
		resp, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
			GrantType: "refresh_token", RefreshToken: issued.Token,
		})
		if err != nil {
			t.Fatalf("issue refresh: %v", err)
		}
		golden := signGolden(t, priv, kid, jwt.MapClaims{
			"iss": equivIssuer, "sub": "cli-1", "client_id": "cli-1",
			"iat": equivFixedNow().Unix(), "exp": exp.Unix(), "jti": equivJTI, "scope": "read", "aud": equivIssuer,
		})
		if resp.AccessToken == golden {
			t.Fatalf("dropped-claim minter still matched the refresh golden")
		}
	})
}
