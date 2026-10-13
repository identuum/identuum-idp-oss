package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// D7: an upstream provider that keeps email out of the id_token (as OIDC Core
// §5.4 allows, and as this OP itself does for scope=email) returns it from its
// userinfo endpoint. The callback fills ONLY the missing email claims from
// userinfo — fetched with the upstream access token, its sub bound to the
// id_token's sub — and then the existing email gate decides.

const userinfoTestAccessToken = "upstream-access-opaque-1"

// userinfoOP is a fake upstream OP whose discovery names a userinfo_endpoint.
type userinfoOP struct {
	h            *callbackHarness
	calls        *int32
	badBearer    *int32
	userinfoCode *int
	userinfoBody *map[string]any
}

func newUserinfoHarness(t *testing.T) *userinfoOP {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "kid-ui-1"
	clientID := "client-ui"
	idToken := new(string)
	calls := new(int32)
	badBearer := new(int32)
	code := new(int)
	*code = http.StatusOK
	body := new(map[string]any)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownOpenIDConfigurationPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"userinfo_endpoint":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks", srv.URL+"/userinfo")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": kid}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q,"access_token":%q,"token_type":"Bearer"}`, *idToken, userinfoTestAccessToken)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if r.Header.Get("Authorization") != "Bearer "+userinfoTestAccessToken {
			atomic.AddInt32(badBearer, 1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if *code != http.StatusOK {
			w.WriteHeader(*code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(*body)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	discovery := NewOIDCDiscoveryService(OIDCDiscoveryOptions{HTTPClient: srv.Client()})
	providers := newFakeIDPConfigRepo()
	states := newFakeOIDCStateRepo()
	pid := uuid.New()
	orgID := uuid.New()
	encSecret, _ := (fakeSecretCipher{}).Encrypt("provider-secret")
	providers.byID[pid] = &domain.IdentityProvider{
		ID: pid, OrganizationID: orgID, Type: domain.IDPTypeOIDC, Active: true,
		Config: domain.ProviderConfig{
			IssuerURL: srv.URL, ClientID: clientID, ClientSecretEncrypted: encSecret,
			RedirectURIs: []string{"https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback"},
			EmailDomains: []string{"example.com"},
		},
	}
	stateKey := "state-ui-xyz"
	nonce := "nonce-ui"
	encVerifier, _ := (fakeSecretCipher{}).Encrypt("verifier-plaintext")
	states.byState[stateKey] = &domain.OIDCState{
		State: stateKey, Nonce: nonce, PKCEVerifierEncrypted: encVerifier, ProviderID: pid,
		OrganizationID: orgID, RedirectURI: "https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback",
		ReturnURL: "/dashboard", CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	users := newCallbackUserRepo()
	sessionRepo := newSessionRepo()
	sessions := NewUserSessionService(nil, sessionRepo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	orgs := newFakeOrgRepo(&domain.Organization{ID: orgID, Active: true})
	svc := NewOIDCCallbackService(lifecycle.NewStartupReport(), OIDCCallbackServiceDeps{
		Providers: providers, Discovery: discovery, States: states, Cipher: fakeSecretCipher{},
		Users: users, Organizations: orgs, Sessions: sessions,
	}, OIDCCallbackServiceOptions{HTTPClient: srv.Client()})

	return &userinfoOP{
		h: &callbackHarness{
			svc: svc, providers: providers, states: states, users: users, sessions: sessions, sessionRepo: sessionRepo,
			orgs: orgs, pid: pid, stateKey: stateKey, nonce: nonce, returnURL: "/dashboard",
			clientID: clientID, orgID: orgID, priv: priv, kid: kid, srv: srv, idToken: idToken,
		},
		calls: calls, badBearer: badBearer, userinfoCode: code, userinfoBody: body,
	}
}

// claimsWithoutEmail is a valid id_token claim set with no email claims.
func (o *userinfoOP) claimsWithoutEmail() jwt.MapClaims {
	c := o.h.validClaims()
	delete(c, "email")
	delete(c, "email_verified")
	return c
}

func (o *userinfoOP) assertRefusedNothingCreated(t *testing.T, res *OIDCCallbackResult, err error) {
	t.Helper()
	if !errors.Is(err, ErrCallbackForbidden) {
		t.Errorf("err = %v, want ErrCallbackForbidden", err)
	}
	if res != nil {
		t.Errorf("result = %+v, want nil (no sign-in)", res)
	}
	if n := len(o.h.users.byID); n != 0 {
		t.Errorf("users created = %d, want 0", n)
	}
	if n := len(o.h.sessionRepo.byID); n != 0 {
		t.Errorf("sessions minted = %d, want 0", n)
	}
}

func (o *userinfoOP) assertUserinfoCalledOnceWithAccessToken(t *testing.T) {
	t.Helper()
	if n := atomic.LoadInt32(o.calls); n != 1 {
		t.Errorf("userinfo calls = %d, want 1", n)
	}
	if n := atomic.LoadInt32(o.badBearer); n != 0 {
		t.Errorf("userinfo requests without the upstream access token as Bearer = %d, want 0", n)
	}
}

// RULE: CALLBACK-USERINFO-EMAIL-1
func TestOIDCCallback_Userinfo_EmailOnlyInUserinfoSignsIn(t *testing.T) {
	o := newUserinfoHarness(t)
	*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.claimsWithoutEmail())
	*o.userinfoBody = map[string]any{"sub": "upstream-user-123", "email": "alice@example.com", "email_verified": true}

	res, err := o.h.call()
	if err != nil {
		t.Fatalf("HandleCallback: %v (email was only in userinfo)", err)
	}
	o.assertUserinfoCalledOnceWithAccessToken(t)
	if res.User == nil || res.User.Email != "alice@example.com" || !res.User.EmailVerified {
		t.Errorf("user = %+v, want alice@example.com verified", res.User)
	}
	if res.User != nil && (res.User.ExternalID == nil || *res.User.ExternalID != o.h.srv.URL+"|upstream-user-123") {
		t.Errorf("ExternalID = %v, want issuer|sub from the id_token", res.User.ExternalID)
	}
	if res.Session == nil {
		t.Errorf("no session minted")
	}
}

func TestOIDCCallback_Userinfo_SubMismatchRefused(t *testing.T) {
	o := newUserinfoHarness(t)
	*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.claimsWithoutEmail())
	*o.userinfoBody = map[string]any{"sub": "someone-else", "email": "alice@example.com", "email_verified": true}

	res, err := o.h.call()
	o.assertUserinfoCalledOnceWithAccessToken(t)
	o.assertRefusedNothingCreated(t, res, err)
}

func TestOIDCCallback_Userinfo_ErrorRefused(t *testing.T) {
	o := newUserinfoHarness(t)
	*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.claimsWithoutEmail())
	*o.userinfoCode = http.StatusInternalServerError

	res, err := o.h.call()
	o.assertUserinfoCalledOnceWithAccessToken(t)
	o.assertRefusedNothingCreated(t, res, err)
}

// Fill only missing claims, and never launder verification: userinfo's
// email_verified attests userinfo's email. When the id_token carries an email
// but no email_verified, a userinfo response for a DIFFERENT address must not
// verify the id_token's address (the P1-3 rule of applyClaimMapping).
func TestOIDCCallback_Userinfo_VerificationBindsToSameEmail(t *testing.T) {
	o := newUserinfoHarness(t)
	c := o.claimsWithoutEmail()
	c["email"] = "bob@example.com"
	*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, c)
	*o.userinfoBody = map[string]any{"sub": "upstream-user-123", "email": "alice@example.com", "email_verified": true}

	res, err := o.h.call()
	o.assertUserinfoCalledOnceWithAccessToken(t)
	o.assertRefusedNothingCreated(t, res, err)
}

// D7: when no email reaches the gate — userinfo refused, mismatched, or not
// offered at all — the refusal names it, so the person reads why.
// RULE: CALLBACK-USERINFO-BINDING-1
func TestOIDCCallback_Userinfo_NoEmailRefusalNamesIt(t *testing.T) {
	t.Run("userinfo error", func(t *testing.T) {
		o := newUserinfoHarness(t)
		*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.claimsWithoutEmail())
		*o.userinfoCode = http.StatusBadGateway
		_, err := o.h.call()
		if !errors.Is(err, ErrCallbackEmailNotShared) {
			t.Errorf("err = %v, want ErrCallbackEmailNotShared", err)
		}
	})
	t.Run("userinfo for another subject", func(t *testing.T) {
		o := newUserinfoHarness(t)
		*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.claimsWithoutEmail())
		*o.userinfoBody = map[string]any{"sub": "someone-else", "email": "alice@example.com", "email_verified": true}
		_, err := o.h.call()
		if !errors.Is(err, ErrCallbackEmailNotShared) {
			t.Errorf("err = %v, want ErrCallbackEmailNotShared", err)
		}
	})
	t.Run("no userinfo endpoint", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		delete(c, "email")
		delete(c, "email_verified")
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		_, err := h.call()
		if !errors.Is(err, ErrCallbackEmailNotShared) {
			t.Errorf("err = %v, want ErrCallbackEmailNotShared", err)
		}
		if n := len(h.sessionRepo.byID); n != 0 {
			t.Errorf("sessions minted = %d, want 0", n)
		}
	})
	t.Run("an unverified address is not reported as not shared", func(t *testing.T) {
		o := newUserinfoHarness(t)
		c := o.claimsWithoutEmail()
		c["email"] = "bob@example.com"
		*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, c)
		*o.userinfoBody = map[string]any{"sub": "upstream-user-123", "email": "alice@example.com", "email_verified": true}
		_, err := o.h.call()
		if !errors.Is(err, ErrCallbackForbidden) || errors.Is(err, ErrCallbackEmailNotShared) {
			t.Errorf("err = %v, want ErrCallbackForbidden, not ErrCallbackEmailNotShared", err)
		}
	})
}

// D7: the optional userinfo endpoint the callback calls with the upstream
// access token is held to the https/host rule of every other discovered
// endpoint (UPSTREAM-URL-HTTPS-1); absent stays accepted.
func TestUpstreamURLGuards_UserinfoEndpoint(t *testing.T) {
	disc := NewOIDCDiscoveryService(OIDCDiscoveryOptions{})
	const head = `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/auth","token_endpoint":"https://idp.example.com/token","jwks_uri":"https://idp.example.com/jwks"`
	for _, ui := range []string{"http://idp.example.com/userinfo", "https://", "ftp://idp.example.com/userinfo", "relative/userinfo"} {
		if _, err := disc.parseAndValidate([]byte(head+`,"userinfo_endpoint":"`+ui+`"}`), "https://idp.example.com"); err == nil {
			t.Errorf("userinfo_endpoint %q must be refused", ui)
		}
	}
	doc, err := disc.parseAndValidate([]byte(head+`,"userinfo_endpoint":"https://idp.example.com/userinfo"}`), "https://idp.example.com")
	if err != nil || doc == nil || doc.UserinfoEndpoint != "https://idp.example.com/userinfo" {
		t.Errorf("an https userinfo_endpoint must be accepted and kept, got doc=%v err=%v", doc, err)
	}
	if doc, err := disc.parseAndValidate([]byte(head+`}`), "https://idp.example.com"); err != nil || doc.UserinfoEndpoint != "" {
		t.Errorf("a document without userinfo_endpoint must still validate, got doc=%v err=%v", doc, err)
	}
}

// Control: email and email_verified in the id_token ⇒ no userinfo call.
func TestOIDCCallback_Userinfo_NotCalledWhenIDTokenHasEmail(t *testing.T) {
	o := newUserinfoHarness(t)
	*o.h.idToken = o.h.signEdDSA(t, o.h.priv, o.h.kid, o.h.validClaims())

	res, err := o.h.call()
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if n := atomic.LoadInt32(o.calls); n != 0 {
		t.Errorf("userinfo calls = %d, want 0 (id_token already carried email)", n)
	}
	if res.User == nil || res.User.Email != "alice@example.com" {
		t.Errorf("user = %+v, want alice@example.com", res.User)
	}
}
