package service

// THE-PKCE-DECISION (owner ruling 1): PKCE is PER-CLIENT — REQUIRED for
// public clients, OPTIONAL for confidential clients. "Optional to SEND,
// never to HONOR": a supplied challenge is still validated (S256 only) and
// a bound challenge is still verified at the token endpoint; a code minted
// WITHOUT a challenge refuses a gratuitous verifier.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// newAuthorizePKCEHarness mirrors newAuthorizeHarness with a controllable
// IsPublic flag on the client.
func newAuthorizePKCEHarness(t *testing.T, isPublic bool) (*AuthorizeService, *fakeAuthorizeSessionLookup) {
	t.Helper()
	repo := newAuthCodeRepo()
	codes := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{
		client: &domain.Client{
			ClientID:     "cli-1",
			Name:         "Test client",
			RedirectURIs: []string{"https://app.example.com/cb"},
			SkipConsent:  true,
			IsPublic:     isPublic,
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
	return svc, sess
}

// PKCE-PUBLIC-REQUIRED: a PUBLIC client without a code_challenge is refused
// with missing-parameters, before any code is minted.
// RULE: PKCE-PER-CLIENT-1
func TestAuthorize_PublicClientWithoutChallengeRejected(t *testing.T) {
	svc, sess := newAuthorizePKCEHarness(t, true)
	req := newAuthorizeRequest("", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = "" // truly absent PKCE, not method-without-challenge
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("err = %v, want ErrAuthorizeMissingParameters — public clients REQUIRE PKCE", err)
	}
}

// A CONFIDENTIAL client may omit PKCE entirely: the code mints and the
// redirect carries it.
func TestAuthorize_ConfidentialClientWithoutChallengeSucceeds(t *testing.T) {
	svc, sess := newAuthorizePKCEHarness(t, false)
	req := newAuthorizeRequest("", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = ""
	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: %v — confidential clients may omit PKCE", err)
	}
	if result.Code == "" {
		t.Error("code is empty")
	}
}

// A code_challenge_method WITHOUT a challenge is malformed for every client
// kind — refused, not silently ignored.
func TestAuthorize_MethodWithoutChallengeRejected(t *testing.T) {
	svc, sess := newAuthorizePKCEHarness(t, false)
	req := newAuthorizeRequest("", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = "S256"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("err = %v, want ErrAuthorizeMissingParameters", err)
	}
}

// A SUPPLIED challenge stays validated even for a confidential client:
// "optional to SEND, never to HONOR" — plain is still refused.
func TestAuthorize_ConfidentialSuppliedPlainChallengeStillRejected(t *testing.T) {
	svc, sess := newAuthorizePKCEHarness(t, false)
	req := newAuthorizeRequest("some-challenge", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = "plain"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeUnsupportedChallenge) {
		t.Errorf("err = %v, want ErrAuthorizeUnsupportedChallenge", err)
	}
}

// ---------- request objects (OIDC §6) ----------

// Request objects are unsupported and REFUSED with the §6.1 sentinels —
// never silently ignored, which would drop the object's real parameters
// (state, nonce, redirect_uri) on the floor. Conformance-measured
// (oidcc-unsigned-request-object-...): ignoring `request` minted a code
// against the OUTER parameters only.
// RULE: AUTHZ-REQUEST-OBJECT-REFUSED-1
func TestAuthorize_RequestObjectRefusedNotIgnored(t *testing.T) {
	svc, sess := newAuthorizePKCEHarness(t, false)

	req := newAuthorizeRequest("", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = ""
	req.RequestObject = "eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6Imlubm VyIn0."
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeRequestNotSupported) {
		t.Errorf("request= err = %v, want ErrAuthorizeRequestNotSupported", err)
	}

	req = newAuthorizeRequest("", authorizePrincipal(sess.session.ID))
	req.CodeChallengeMethod = ""
	req.RequestURIParam = "https://rp.example.com/request.jwt"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeRequestURINotSupported) {
		t.Errorf("request_uri= err = %v, want ErrAuthorizeRequestURINotSupported", err)
	}
}

// ---------- token-endpoint side ----------

func noChallengeCreateInput() CreateAuthorizationCodeInput {
	in := baseCreateInput("")
	in.CodeChallengeMethod = ""
	return in
}

// A code minted WITHOUT a challenge consumes cleanly with no verifier.
func TestConsume_NoChallengeNoVerifierSucceeds(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	created, err := svc.Create(context.Background(), noChallengeCreateInput())
	if err != nil {
		t.Fatalf("create without challenge: %v", err)
	}
	consumed, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:        created.Code,
		ClientID:    "cli-1",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.Scope != "openid profile" {
		t.Errorf("scope = %q", consumed.Scope)
	}
}

// Strict BCP posture: a GRATUITOUS verifier against a challenge-less code is
// invalid_grant — a verifier that was never bound must never "pass".
func TestConsume_NoChallengeGratuitousVerifierRejected(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	created, err := svc.Create(context.Background(), noChallengeCreateInput())
	if err != nil {
		t.Fatalf("create without challenge: %v", err)
	}
	_, err = svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: "gratuitous-verifier-never-bound-to-a-challenge",
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v, want ErrAuthCodeInvalidGrant", err)
	}
}

// NEVER-TO-HONOR: once a challenge IS bound, the verifier is mandatory —
// omitting it fails even though PKCE was "optional" for the client.
func TestConsume_BoundChallengeMissingVerifierRejected(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	_, challenge := pkceVerifierAndChallenge(t)
	created, err := svc.Create(context.Background(), baseCreateInput(challenge))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:        created.Code,
		ClientID:    "cli-1",
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v, want ErrAuthCodeInvalidGrant — a bound challenge is ALWAYS verified", err)
	}
}
