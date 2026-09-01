package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- fakes ----------

type fakeAuthorizeClientLookup struct {
	client *domain.Client
	err    error
}

func (f *fakeAuthorizeClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return f.client, f.err
}

type fakeAuthorizeSessionLookup struct {
	session *domain.Session
	err     error
}

func (f *fakeAuthorizeSessionLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.Session, error) {
	return f.session, f.err
}

type fakeAudienceLookup struct {
	resource *domain.APIResource
	err      error
}

func (f *fakeAudienceLookup) LookupAudience(_ context.Context, _ string) (*domain.APIResource, error) {
	return f.resource, f.err
}

func newAuthorizeHarness(t *testing.T, skipConsent bool) (*AuthorizeService, *inMemoryAuthCodeRepo, *fakeAuthorizeSessionLookup) {
	t.Helper()
	repo := newAuthCodeRepo()
	codes := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{
		client: &domain.Client{
			ClientID:     "cli-1",
			Name:         "Test client",
			RedirectURIs: []string{"https://app.example.com/cb"},
			SkipConsent:  skipConsent,
		},
	}
	sess := &fakeAuthorizeSessionLookup{
		session: &domain.Session{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			IsValid:   true,
			CreatedAt: time.Now().Add(-time.Minute),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithSessionLookup(sess)
	return svc, repo, sess
}

func newAuthorizeRequest(challenge string, principal *domain.Principal) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "cli-1",
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid profile",
		State:               "xyz123",
		Nonce:               "nonce-1",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Principal:           principal,
	}
}

func authorizePrincipal(sessionID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		SessionID:      sessionID,
		Email:          "alice@example.com",
		Role:           domain.RoleOrgUser,
	}
}

func authorizeChallenge(t *testing.T) (string, string) {
	t.Helper()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------- P0-5: tenant deletion is an authentication boundary ----------

// A principal whose organization is non-operational (deactivated OR deleted)
// MUST NOT get an authorization code minted; an operational org still issues.
func TestAuthorize_NonOperationalOrgRejected(t *testing.T) {
	_, challenge := authorizeChallenge(t)

	t.Run("deactivated org rejected, no code minted", func(t *testing.T) {
		svc, repo, sess := newAuthorizeHarness(t, true) // skipConsent → a live org would issue
		orgID := uuid.New()
		svc.WithOrganizationLookup(newFakeOrgRepo(&domain.Organization{ID: orgID, Active: false}))
		principal := authorizePrincipal(sess.session.ID)
		principal.OrganizationID = orgID
		if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, principal)); !errors.Is(err, ErrAuthorizeLoginRequired) {
			t.Fatalf("deactivated org: err = %v, want ErrAuthorizeLoginRequired", err)
		}
		if len(repo.byID) != 0 {
			t.Errorf("deactivated org: %d code(s) minted, want 0", len(repo.byID))
		}
	})

	t.Run("deleted org rejected", func(t *testing.T) {
		svc, repo, sess := newAuthorizeHarness(t, true)
		orgID := uuid.New()
		now := time.Now()
		svc.WithOrganizationLookup(newFakeOrgRepo(&domain.Organization{ID: orgID, Active: true, DeletedAt: &now}))
		principal := authorizePrincipal(sess.session.ID)
		principal.OrganizationID = orgID
		if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, principal)); !errors.Is(err, ErrAuthorizeLoginRequired) {
			t.Fatalf("deleted org: err = %v, want ErrAuthorizeLoginRequired", err)
		}
		if len(repo.byID) != 0 {
			t.Errorf("deleted org: %d code(s) minted, want 0", len(repo.byID))
		}
	})

	t.Run("operational org still issues", func(t *testing.T) {
		svc, repo, sess := newAuthorizeHarness(t, true)
		orgID := uuid.New()
		svc.WithOrganizationLookup(newFakeOrgRepo(&domain.Organization{ID: orgID, Active: true}))
		principal := authorizePrincipal(sess.session.ID)
		principal.OrganizationID = orgID
		res, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, principal))
		if err != nil {
			t.Fatalf("operational org: err = %v, want success", err)
		}
		if res == nil || res.Code == "" {
			t.Fatalf("operational org: a code must be issued")
		}
		if len(repo.byID) != 1 {
			t.Errorf("operational org: %d code(s) minted, want 1", len(repo.byID))
		}
	})
}

// ---------- Construction ----------

func TestNewAuthorizeService_NilClientLookupPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil client lookup did not panic")
		}
	}()
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{})
	_ = NewAuthorizeService(nil, nil, codes, AuthorizeServiceOptions{Issuer: "x"})
}

func TestNewAuthorizeService_NilCodesPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil codes did not panic")
		}
	}()
	_ = NewAuthorizeService(nil, &fakeAuthorizeClientLookup{}, nil, AuthorizeServiceOptions{Issuer: "x"})
}

func TestNewAuthorizeService_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("empty issuer did not panic")
		}
	}()
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{})
	_ = NewAuthorizeService(nil, &fakeAuthorizeClientLookup{}, codes, AuthorizeServiceOptions{})
}

// ---------- Pre-redirect-uri 400 failures ----------

func TestAuthorize_MissingClientIDReturnsDirect400(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(uuid.New()))
	req.ClientID = ""
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_UnknownClientReturnsInvalidClient(t *testing.T) {
	repo := newAuthCodeRepo()
	codes := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{client: nil}
	svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"})
	_, challenge := authorizeChallenge(t)
	if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, authorizePrincipal(uuid.New()))); !errors.Is(err, ErrAuthorizeInvalidClient) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_UnregisteredRedirectURIIsInvalidRedirectURI(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(uuid.New()))
	req.RedirectURI = "https://imposter.example.com/cb"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeInvalidRedirectURI) {
		t.Errorf("err = %v", err)
	}
}

// ---------- Redirect-safe failures ----------

func TestAuthorize_NonCodeResponseTypeIsUnsupported(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(uuid.New()))
	req.ResponseType = "token"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeUnsupportedResponseType) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_MissingCodeChallengeRejected(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	req := newAuthorizeRequest("", authorizePrincipal(uuid.New()))
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_PlainChallengeMethodRejected(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(uuid.New()))
	req.CodeChallengeMethod = "plain"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeUnsupportedChallenge) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_NoPrincipalIsLoginRequired(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, nil)
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_RevokedSessionIsLoginRequired(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, true)
	now := time.Now()
	sess.session.Revoke(now, "revoked")
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_NonPreapprovedClientIsConsentRequired(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, false)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeConsentRequired) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_UnknownAudienceIsInvalidTarget(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, true)
	svc.WithAudienceLookup(&fakeAudienceLookup{resource: nil})
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	req.Audience = "https://api.unknown.example.com"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeInvalidTarget) {
		t.Errorf("err = %v", err)
	}
}

// ---------- Success path ----------

func TestAuthorize_SuccessReturnsRedirectWithCodeAndState(t *testing.T) {
	svc, repo, sess := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if result.Code == "" {
		t.Errorf("code is empty")
	}
	u, parseErr := url.Parse(result.RedirectURL)
	if parseErr != nil {
		t.Fatalf("url parse: %v", parseErr)
	}
	if u.Query().Get("code") != result.Code {
		t.Errorf("code query mismatch: got %q, want %q", u.Query().Get("code"), result.Code)
	}
	if u.Query().Get("state") != "xyz123" {
		t.Errorf("state echo = %q", u.Query().Get("state"))
	}
	if u.Query().Get("iss") != "https://idp.test" {
		t.Errorf("iss = %q", u.Query().Get("iss"))
	}
	if !strings.HasPrefix(result.RedirectURL, "https://app.example.com/cb") {
		t.Errorf("redirect_url = %q", result.RedirectURL)
	}
	// The stored row holds only the hash; the wire code must NOT
	// be searchable in the row by code text.
	for _, row := range repo.byID {
		if strings.Contains(row.CodeHash, result.Code) {
			t.Errorf("stored hash contains raw code")
		}
	}
}

func TestAuthorize_OmittedStateOmittedFromRedirect(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	req.State = ""
	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(result.RedirectURL)
	if u.Query().Get("state") != "" {
		t.Errorf("state should be absent, got %q", u.Query().Get("state"))
	}
}

// ---------- BuildErrorRedirect ----------

func TestBuildErrorRedirect_StateEchoedIssAppended(t *testing.T) {
	svc, _, _ := newAuthorizeHarness(t, true)
	got, err := svc.BuildErrorRedirect("https://app.example.com/cb", "consent_required", "xyz")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("error") != "consent_required" {
		t.Errorf("error = %q", u.Query().Get("error"))
	}
	if u.Query().Get("state") != "xyz" {
		t.Errorf("state = %q", u.Query().Get("state"))
	}
	if u.Query().Get("iss") != "https://idp.test" {
		t.Errorf("iss = %q", u.Query().Get("iss"))
	}
}

// ---------- DefaultResponseTypeAndMethod (RFC 6749 / OIDC defaults) ----------

// response_type is REQUIRED (RFC 6749 §4.1.1) — an absent value is refused
// with the redirect-safe unsupported_response_type sentinel, never silently
// defaulted to "code". THE-PKCE-DECISION conformance measurement: the old
// default minted a code for a malformed request (oidcc-response-type-missing).
// RULE: AUTHZ-RESPONSE-TYPE-REQUIRED-1
func TestAuthorize_EmptyResponseTypeRejected(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	req.ResponseType = ""
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeUnsupportedResponseType) {
		t.Errorf("err = %v, want ErrAuthorizeUnsupportedResponseType", err)
	}
}

func TestAuthorize_EmptyChallengeMethodDefaultsToS256(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, true)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = ""
	if _, err := svc.Authorize(context.Background(), req); err != nil {
		t.Errorf("err = %v", err)
	}
}

// ---------- Consent integration ----------

func TestAuthorize_RememberedConsentCoversBypassesConsentRequired(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, false) // SkipConsent=false
	consent := NewConsentService(nil, newConsentRepo())
	svc.WithConsentService(consent)
	principal := authorizePrincipal(sess.session.ID)
	_, _ = consent.Grant(context.Background(), GrantConsentInput{
		UserID:   principal.UserID,
		ClientID: "cli-1",
		Scope:    "openid profile",
	})
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	if _, err := svc.Authorize(context.Background(), req); err != nil {
		t.Errorf("remembered consent did not bypass consent_required: %v", err)
	}
}

func TestAuthorize_PromptConsentForcesConsentEvenWithRemembered(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, false)
	consent := NewConsentService(nil, newConsentRepo())
	svc.WithConsentService(consent)
	principal := authorizePrincipal(sess.session.ID)
	_, _ = consent.Grant(context.Background(), GrantConsentInput{
		UserID:   principal.UserID,
		ClientID: "cli-1",
		Scope:    "openid profile",
	})
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.Prompt = "consent"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeConsentRequired) {
		t.Errorf("prompt=consent did not force consent: %v", err)
	}
}

func TestAuthorize_RememberedConsentMissingScopeStillRequiresConsent(t *testing.T) {
	svc, _, sess := newAuthorizeHarness(t, false)
	consent := NewConsentService(nil, newConsentRepo())
	svc.WithConsentService(consent)
	principal := authorizePrincipal(sess.session.ID)
	_, _ = consent.Grant(context.Background(), GrantConsentInput{
		UserID:   principal.UserID,
		ClientID: "cli-1",
		Scope:    "openid",
	})
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.Scope = "openid offline_access"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeConsentRequired) {
		t.Errorf("missing offline_access in stored row did not trip consent: %v", err)
	}
}
