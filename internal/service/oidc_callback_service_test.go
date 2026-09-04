package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

type callbackHarness struct {
	svc              *OIDCCallbackService
	providers        *fakeIDPConfigRepo
	states           *fakeOIDCStateRepo
	users            *fakeUserRepoForCallback
	sessions         *UserSessionService
	sessionRepo      *inMemoryUserSessionRepo
	orgs             *fakeOrgRepo
	pid              uuid.UUID
	stateKey         string
	nonce            string
	returnURL        string
	clientID         string
	orgID            uuid.UUID
	priv             ed25519.PrivateKey
	kid              string
	srv              *httptest.Server
	idToken          *string // set per test — what /token returns
	capturedVerifier *string
	capturedSecret   *string
}

func newCallbackHarness(t *testing.T) *callbackHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "kid-1"
	clientID := "client-abc"
	idToken := new(string)
	capturedVerifier := new(string)
	capturedSecret := new(string)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownOpenIDConfigurationPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": kid}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*capturedVerifier = r.FormValue("code_verifier")
		*capturedSecret = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q,"token_type":"Bearer"}`, *idToken)
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
		ID:             pid,
		OrganizationID: orgID,
		Type:           domain.IDPTypeOIDC,
		Active:         true,
		Config: domain.ProviderConfig{
			IssuerURL:             srv.URL,
			ClientID:              clientID,
			ClientSecretEncrypted: encSecret,
			RedirectURIs:          []string{"https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback"},
			EmailDomains:          []string{"example.com"},
		},
	}

	stateKey := "state-token-xyz"
	nonce := "nonce-abc"
	returnURL := "/dashboard"
	encVerifier, _ := (fakeSecretCipher{}).Encrypt("verifier-plaintext")
	states.byState[stateKey] = &domain.OIDCState{
		State:                 stateKey,
		Nonce:                 nonce,
		PKCEVerifierEncrypted: encVerifier,
		ProviderID:            pid,
		OrganizationID:        orgID,
		RedirectURI:           "https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback",
		ReturnURL:             returnURL,
		CodeChallengeMethod:   "S256",
		ExpiresAt:             time.Now().Add(5 * time.Minute),
	}

	users := newCallbackUserRepo()
	sessionRepo := newSessionRepo()
	sessions := NewUserSessionService(nil, sessionRepo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	orgs := newFakeOrgRepo(&domain.Organization{ID: orgID, Active: true})
	svc := NewOIDCCallbackService(lifecycle.NewStartupReport(), OIDCCallbackServiceDeps{
		Providers:     providers,
		Discovery:     discovery,
		States:        states,
		Cipher:        fakeSecretCipher{},
		Users:         users,
		Organizations: orgs,
		Sessions:      sessions,
	}, OIDCCallbackServiceOptions{HTTPClient: srv.Client()})

	return &callbackHarness{
		svc: svc, providers: providers, states: states, users: users, sessions: sessions, sessionRepo: sessionRepo,
		orgs: orgs,
		pid:  pid, stateKey: stateKey, nonce: nonce, returnURL: returnURL,
		clientID: clientID, orgID: orgID, priv: priv, kid: kid, srv: srv, idToken: idToken,
		capturedVerifier: capturedVerifier, capturedSecret: capturedSecret,
	}
}

// validCallbackClaims are a well-formed ID token's claims for this harness.
func (h *callbackHarness) validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":            h.srv.URL,
		"aud":            h.clientID,
		"sub":            "upstream-user-123",
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nbf":            now.Add(-1 * time.Minute).Unix(),
		"nonce":          h.nonce,
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
		"acr":            "urn:mace:incommon:iap:silver",
	}
}

func (h *callbackHarness) signEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (h *callbackHarness) call() (*OIDCCallbackResult, error) {
	return h.svc.HandleCallback(context.Background(), h.pid, h.stateKey, "auth-code-1", "203.0.113.7", "test-agent")
}

// (happy path) A valid ID token from an allow-listed domain JIT-provisions a
// passwordless federated LOCAL user with the ExternalID/Issuer stamped, MINTS a
// local session (ACR derived from the upstream acr), and returns the STORED
// sanitized ReturnURL; the token exchange sent the DECRYPTED PKCE verifier +
// client_secret (never ciphertext).
func TestOIDCCallback_HappyPathExternalUser(t *testing.T) {
	h := newCallbackHarness(t)
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())

	res, err := h.call()
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	u := res.User
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q", u.Email)
	}
	if u.Name == nil || *u.Name != "Alice" {
		t.Errorf("name = %v, want Alice", u.Name)
	}
	if u.ExternalID == nil || *u.ExternalID != h.srv.URL+"|upstream-user-123" {
		t.Errorf("ExternalID = %v, want issuer|sub", u.ExternalID)
	}
	if u.OIDCIssuer == nil || *u.OIDCIssuer != h.srv.URL {
		t.Errorf("OIDCIssuer = %v, want %q", u.OIDCIssuer, h.srv.URL)
	}
	if !u.EmailVerified {
		t.Errorf("EmailVerified = false, want true")
	}
	if u.PasswordHash != domain.NoPasswordSentinel {
		t.Errorf("PasswordHash = %q, want the no-password sentinel", u.PasswordHash)
	}
	if u.AuthSource != domain.AuthSourceIDJag {
		t.Errorf("AuthSource = %q, want id_jag", u.AuthSource)
	}
	if u.OrganizationID != h.orgID {
		t.Errorf("OrganizationID = %v, want %v", u.OrganizationID, h.orgID)
	}
	// A local session was minted for THIS user via the shared UserSessionService,
	// with a non-empty refresh token and the ACR stamped from the upstream acr.
	if res.Session == nil || res.Session.UserID != u.ID {
		t.Fatalf("session not minted for the resolved user: %+v", res.Session)
	}
	if res.RefreshToken == "" {
		t.Errorf("no refresh token issued")
	}
	if res.Session.Acr != auth.ACRMFA {
		t.Errorf("session Acr = %q, want %q (upstream acr → ladder rung)", res.Session.Acr, auth.ACRMFA)
	}
	if res.Session.IPAddress == nil || *res.Session.IPAddress != "203.0.113.7" {
		t.Errorf("session IPAddress = %v, want the request IP recorded", res.Session.IPAddress)
	}
	// The redirect target is the STORED, already-sanitized ReturnURL (not
	// re-derived from the provider response).
	if res.ReturnURL != h.returnURL {
		t.Errorf("ReturnURL = %q, want the stored %q", res.ReturnURL, h.returnURL)
	}
	// The persisted session carries the same ACR (mint reused UserSessionService).
	if persisted, ok := h.sessionRepo.byID[res.Session.ID]; !ok || persisted.Acr != auth.ACRMFA {
		t.Errorf("persisted session missing or wrong ACR: %+v", persisted)
	}
	// The exchange sent the DECRYPTED verifier + secret, not the ciphertext.
	if *h.capturedVerifier != "verifier-plaintext" {
		t.Errorf("token exchange sent code_verifier %q, want decrypted plaintext", *h.capturedVerifier)
	}
	if *h.capturedSecret != "provider-secret" {
		t.Errorf("token exchange sent client_secret %q, want decrypted plaintext", *h.capturedSecret)
	}
}

// P0-4: tenant deletion is an authentication boundary. When the provider's
// organization is DEACTIVATED, the callback refuses BEFORE resolving the local
// user — no JIT-create, and NO session minted.
func TestOIDCCallback_DeactivatedOrg_RefusesJITAndSession(t *testing.T) {
	h := newCallbackHarness(t)
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
	h.orgs.byID[h.orgID].Active = false // deactivate the tenant

	res, err := h.call()
	if !errors.Is(err, ErrCallbackStateInvalid) {
		t.Fatalf("deactivated org: err = %v, want ErrCallbackStateInvalid", err)
	}
	if res != nil {
		t.Fatalf("deactivated org: result must be nil (no login material)")
	}
	if len(h.sessionRepo.byID) != 0 {
		t.Errorf("deactivated org: %d session(s) minted, want 0", len(h.sessionRepo.byID))
	}
	if len(h.users.byID) != 0 {
		t.Errorf("deactivated org: %d user(s) JIT-created, want 0", len(h.users.byID))
	}
}

// P0-4: when the provider's organization is soft-DELETED (deleted_at set), the
// callback likewise refuses and mints no session. This exercises the
// IsOperational() branch (the org row still resolves but is not operational).
func TestOIDCCallback_DeletedOrg_RefusesJITAndSession(t *testing.T) {
	h := newCallbackHarness(t)
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
	now := time.Now()
	h.orgs.byID[h.orgID].DeletedAt = &now // soft-delete the tenant (Active stays true)

	res, err := h.call()
	if !errors.Is(err, ErrCallbackStateInvalid) {
		t.Fatalf("deleted org: err = %v, want ErrCallbackStateInvalid", err)
	}
	if res != nil {
		t.Fatalf("deleted org: result must be nil")
	}
	if len(h.sessionRepo.byID) != 0 {
		t.Errorf("deleted org: %d session(s) minted, want 0", len(h.sessionRepo.byID))
	}
}

// P0-4: the refusal covers the MATCH path too — even when a local user for the
// federated identity ALREADY exists, a non-operational org blocks the match and
// mints no session (the org gate runs before resolveLocalUser).
func TestOIDCCallback_DeadOrg_RefusesExistingUserMatch(t *testing.T) {
	h := newCallbackHarness(t)
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
	// Pre-seed a matching local user (email+org) so the callback would
	// otherwise take the MATCH branch rather than JIT-create.
	uid := uuid.New()
	h.users.byID[uid] = &domain.User{
		ID:             uid,
		OrganizationID: h.orgID,
		Email:          "alice@example.com",
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
	}
	h.orgs.byID[h.orgID].Active = false // tenant deactivated

	res, err := h.call()
	if !errors.Is(err, ErrCallbackStateInvalid) {
		t.Fatalf("dead org + existing user: err = %v, want ErrCallbackStateInvalid", err)
	}
	if res != nil || len(h.sessionRepo.byID) != 0 {
		t.Fatalf("dead org + existing user: no session must be minted (res=%v sessions=%d)", res != nil, len(h.sessionRepo.byID))
	}
}

// (ACR mapping) The session ACR rung is derived from the upstream acr via
// auth.MapUpstreamACRToLadder — its first production caller. A MEASURED
// upstream value is stamped verbatim or mapped onto the ladder; an ASSUMED one
// is not stamped at all.
//
// THE-ACR-AMR-TRUTH (2026-09-04) flipped the first case. It used to assert that
// an absent upstream acr stamps the ladder's assumed default, urn:identuum:loa:mfa
// — i.e. that a relying party reading acr would be told the user completed
// multi-factor authentication because the upstream IdP said nothing at all. The
// mapper still answers (ACRMFA, assumedDefault=true) as a floor for its callers;
// mintSession now honours the flag and stamps no acr, so the id_token omits the
// claim rather than asserting an unperformed one. Empty also fails CLOSED
// against any requested rung (acrLadder[""] is 0).
//
// RULE: ACR-ASSUMED-NEVER-STAMPED-1
func TestOIDCCallback_ACRStampedFromUpstream(t *testing.T) {
	cases := []struct {
		name     string
		acr      any // set into the claim; nil ⇒ omit
		wantRung string
	}{
		{"absent acr → assumed, so NO acr is stamped", nil, ""},
		{"password loa (0)", "0", auth.ACRPassword},
		{"phishing-resistant marker", "phishing-resistant-webauthn", auth.ACRPhishingResistant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			c := h.validClaims()
			if tc.acr == nil {
				delete(c, "acr")
			} else {
				c["acr"] = tc.acr
			}
			*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
			res, err := h.call()
			if err != nil {
				t.Fatalf("HandleCallback: %v", err)
			}
			if res.Session.Acr != tc.wantRung {
				t.Errorf("session Acr = %q, want %q", res.Session.Acr, tc.wantRung)
			}
		})
	}
}

// (session-mint failure) A session-mint failure after the user is resolved
// surfaces as ErrCallbackSessionFailed (500-class); no result is returned.
func TestOIDCCallback_SessionMintFailure(t *testing.T) {
	h := newCallbackHarness(t)
	h.sessionRepo.createErr = context.DeadlineExceeded
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
	res, err := h.call()
	if !errors.Is(err, ErrCallbackSessionFailed) {
		t.Errorf("err = %v, want ErrCallbackSessionFailed", err)
	}
	if res != nil {
		t.Errorf("a result was returned on session-mint failure: %+v", res)
	}
}

// (strict validation) alg=none, wrong iss, wrong aud, expired, nonce mismatch,
// and a foreign signature are ALL rejected as validation failures.
func TestOIDCCallback_StrictValidationRejections(t *testing.T) {
	t.Run("alg=none", func(t *testing.T) {
		h := newCallbackHarness(t)
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, h.validClaims())
		tok.Header["kid"] = h.kid
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		*h.idToken = s
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("alg=none: err = %v, want ErrCallbackValidationFailed", err)
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		c["iss"] = "https://attacker.example"
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("wrong iss: err = %v", err)
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		c["aud"] = "some-other-client"
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("wrong aud: err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		c["exp"] = time.Now().Add(-1 * time.Minute).Unix()
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("expired: err = %v", err)
		}
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		c["nonce"] = "not-the-stored-nonce"
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("nonce mismatch: err = %v", err)
		}
	})
	t.Run("foreign signature", func(t *testing.T) {
		h := newCallbackHarness(t)
		_, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
		// Same kid so the provider JWKS returns the REAL key, but the token is
		// signed by a foreign key → signature verification fails.
		*h.idToken = h.signEdDSA(t, foreignPriv, h.kid, h.validClaims())
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("foreign signature: err = %v", err)
		}
	})
}

// P1-1: an upstream ID token that OMITS exp is rejected (never-expiring token),
// and one that OMITS sub is rejected — both at validation, before any user is
// resolved or session minted. This is the mandatory-claims fix; the Slice-5
// strict-rejection suite above stays unchanged.
func TestOIDCCallback_MandatoryClaims(t *testing.T) {
	t.Run("no exp rejected", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		delete(c, "exp")
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("no exp: err = %v, want ErrCallbackValidationFailed", err)
		}
		if len(h.users.byID) != 0 || len(h.sessionRepo.byID) != 0 {
			t.Errorf("no exp: nothing should be provisioned (users=%d sessions=%d)", len(h.users.byID), len(h.sessionRepo.byID))
		}
	})
	t.Run("no sub rejected", func(t *testing.T) {
		h := newCallbackHarness(t)
		c := h.validClaims()
		delete(c, "sub")
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
			t.Errorf("no sub: err = %v, want ErrCallbackValidationFailed", err)
		}
		if len(h.users.byID) != 0 {
			t.Errorf("no sub: no user should be created, got %d", len(h.users.byID))
		}
	})
}

// P1-2: an EMPTY sub must not collapse into a colliding "issuer|" ExternalID.
// The login is rejected and NO user is created — even though iss/aud/nonce and
// the signature are all valid.
func TestOIDCCallback_EmptySubNoIdentityCollapse(t *testing.T) {
	h := newCallbackHarness(t)
	c := h.validClaims()
	c["sub"] = "   " // whitespace-only: passes the parser's non-empty-string check, caught by the ExternalID guard
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
	if _, err := h.call(); !errors.Is(err, ErrCallbackValidationFailed) {
		t.Errorf("empty sub: err = %v, want ErrCallbackValidationFailed", err)
	}
	if len(h.users.byID) != 0 {
		t.Errorf("empty sub: no user (no 'issuer|' identity) must be created, got %d", len(h.users.byID))
	}
	if len(h.sessionRepo.byID) != 0 {
		t.Errorf("empty sub: no session must be minted, got %d", len(h.sessionRepo.byID))
	}
}

// P1-3: when the org remaps email to a NON-standard claim, the standard
// email_verified claim does NOT verify the remapped identifier. A mapped email
// that is verified ONLY by the standard email_verified is treated as UNVERIFIED
// and refused by the JIT gate — no user is created. When the org ALSO maps a
// verification source, the mapped email links normally.
func TestOIDCCallback_MappedEmailVerificationBinding(t *testing.T) {
	t.Run("mapped email unverified without a mapped verification source", func(t *testing.T) {
		h := newCallbackHarness(t)
		h.providers.byID[h.pid].Config.ClaimMapping = map[string]string{"email": "mail"}
		c := h.validClaims()
		// Standard email is verified; the MAPPED claim carries a different,
		// allow-listed address whose verification is NOT asserted anywhere.
		c["email"] = "alice@example.com"
		c["email_verified"] = true
		c["mail"] = "attacker@example.com"
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		if _, err := h.call(); !errors.Is(err, ErrCallbackForbidden) {
			t.Errorf("mapped-but-unverified email: err = %v, want ErrCallbackForbidden", err)
		}
		if len(h.users.byID) != 0 {
			t.Errorf("mapped-but-unverified email: no user must be created, got %d", len(h.users.byID))
		}
	})
	t.Run("mapped email links when its own verification source is asserted", func(t *testing.T) {
		h := newCallbackHarness(t)
		h.providers.byID[h.pid].Config.ClaimMapping = map[string]string{"email": "mail", "email_verified": "mail_verified"}
		c := h.validClaims()
		c["email"] = "alice@example.com"
		c["email_verified"] = false // standard claim unverified — must not matter
		c["mail"] = "bob@example.com"
		c["mail_verified"] = true
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
		res, err := h.call()
		if err != nil {
			t.Fatalf("mapped-and-verified email: %v", err)
		}
		if res.User.Email != "bob@example.com" || !res.User.EmailVerified {
			t.Errorf("mapped-and-verified email: user = {email:%q verified:%v}, want bob@example.com verified", res.User.Email, res.User.EmailVerified)
		}
	})
}

// (state single-use) A replay of the same state fails: the first callback
// atomically consumes (deletes) it, so the second ConsumeByState finds nothing.
// RULE: OIDC-STATE-1
func TestOIDCCallback_StateSingleUse(t *testing.T) {
	h := newCallbackHarness(t)
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())

	// PREMISE (non-emptiness): there must BE a seeded state to consume —
	// otherwise the emptiness check below passes vacuously against a
	// harness that never armed a state row.
	if len(h.states.byState) == 0 {
		t.Fatal("PREMISE broken: no seeded OIDC state — consumption check would be vacuous")
	}

	if _, err := h.call(); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if len(h.states.byState) != 0 {
		t.Errorf("state not consumed after first callback: %d remain", len(h.states.byState))
	}
	if _, err := h.call(); !errors.Is(err, ErrCallbackStateInvalid) {
		t.Errorf("replay: err = %v, want ErrCallbackStateInvalid", err)
	}
}

// (abort paths) missing state/code, expired state, provider-mismatch, and an
// exchange failure map to their sentinels; no ExternalUser is produced.
func TestOIDCCallback_AbortPaths(t *testing.T) {
	t.Run("missing code", func(t *testing.T) {
		h := newCallbackHarness(t)
		_, err := h.svc.HandleCallback(context.Background(), h.pid, h.stateKey, "", "", "")
		if !errors.Is(err, ErrCallbackStateInvalid) {
			t.Errorf("missing code: err = %v", err)
		}
	})
	t.Run("unknown state", func(t *testing.T) {
		h := newCallbackHarness(t)
		_, err := h.svc.HandleCallback(context.Background(), h.pid, "no-such-state", "c", "", "")
		if !errors.Is(err, ErrCallbackStateInvalid) {
			t.Errorf("unknown state: err = %v", err)
		}
	})
	t.Run("expired state", func(t *testing.T) {
		h := newCallbackHarness(t)
		h.states.byState[h.stateKey].ExpiresAt = time.Now().Add(-1 * time.Minute)
		*h.idToken = h.signEdDSA(t, h.priv, h.kid, h.validClaims())
		_, err := h.call()
		if !errors.Is(err, ErrCallbackStateInvalid) {
			t.Errorf("expired state: err = %v", err)
		}
	})
	t.Run("provider mismatch", func(t *testing.T) {
		h := newCallbackHarness(t)
		_, err := h.svc.HandleCallback(context.Background(), uuid.New(), h.stateKey, "c", "", "")
		if !errors.Is(err, ErrCallbackStateInvalid) {
			t.Errorf("provider mismatch: err = %v", err)
		}
	})
	t.Run("exchange failure (no id_token)", func(t *testing.T) {
		h := newCallbackHarness(t)
		*h.idToken = "" // token endpoint returns an empty id_token
		_, err := h.call()
		if !errors.Is(err, ErrCallbackExchangeFailed) {
			t.Errorf("exchange failure: err = %v, want ErrCallbackExchangeFailed", err)
		}
	})
}
