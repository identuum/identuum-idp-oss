package service

// claims_param_consent_test.go — THE-CLAIMS-PARAMETER through the service
// layer: AuthorizeService parses the OIDC §5.5 request, the consent gate
// covers claims like scopes, the code row carries the consented request, and
// UserTokenService stamps consented ∩ role-permitted onto the access token.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type claimsParamHarness struct {
	authz   *AuthorizeService
	codes   *inMemoryAuthCodeRepo
	consent *ConsentService
	req     AuthorizeRequest
	user    *domain.User
	session *domain.Session
	tokens  *UserTokenService
}

func newClaimsParamHarness(t *testing.T) *claimsParamHarness {
	t.Helper()
	authz, codeRepo, sess := newAuthorizeHarness(t, false) // consent REQUIRED
	consent := NewConsentService(nil, newConsentRepo())
	authz.WithConsentService(consent)
	_, challenge := authorizeChallenge(t)
	principal := authorizePrincipal(sess.session.ID)
	req := newAuthorizeRequest(challenge, principal)
	req.Scope = "openid"
	tokens, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	user.ID = principal.UserID
	return &claimsParamHarness{authz: authz, codes: codeRepo, consent: consent, req: req, user: user, session: session, tokens: tokens}
}

func (h *claimsParamHarness) grant(t *testing.T, claimTokens ...string) {
	t.Helper()
	if _, err := h.consent.Grant(context.Background(), GrantConsentInput{
		UserID: h.req.Principal.UserID, ClientID: "cli-1", Audience: "", Scope: "openid", Claims: claimTokens,
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
}

func (h *claimsParamHarness) onlyCodeRow(t *testing.T) *domain.OAuthAuthorizationCode {
	t.Helper()
	if len(h.codes.byID) != 1 {
		t.Fatalf("want exactly one code row, got %d", len(h.codes.byID))
	}
	for _, row := range h.codes.byID {
		return row
	}
	return nil
}

func (h *claimsParamHarness) tokenUserInfoClaims(t *testing.T, role domain.UserRole, consented []string) []any {
	t.Helper()
	h.user.Role = role
	resp, err := h.tokens.IssueForConsentedClient(context.Background(), h.user, h.session, "cli-1", "openid", consented)
	if err != nil {
		t.Fatalf("IssueForConsentedClient: %v", err)
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	uc, _ := tok.Claims.(jwt.MapClaims)["userinfo_claims"].([]any)
	if (len(uc) == 0) != (len(resp.UserInfoClaims) == 0) {
		t.Fatalf("Response.UserInfoClaims %v disagrees with the token claim %v", resp.UserInfoClaims, uc)
	}
	return uc
}

// RULE: CLAIMS-PARAM-CONSENT-1
func TestClaimsParameter_ConsentGatedAndRoleIntersected(t *testing.T) {
	t.Run("unconsented requested claim never lands", func(t *testing.T) {
		h := newClaimsParamHarness(t)
		h.grant(t) // scope consented, NO claims
		h.req.Claims = `{"userinfo":{"name":{"essential":true}}}`
		if _, err := h.authz.Authorize(context.Background(), h.req); !errors.Is(err, ErrAuthorizeConsentRequired) {
			t.Fatalf("err = %v, want ErrAuthorizeConsentRequired — consent covers scope but not the claim", err)
		}
		if len(h.codes.byID) != 0 {
			t.Fatalf("no code may be minted under an unconsented claim; %d minted", len(h.codes.byID))
		}
	})

	t.Run("consented claim lands on the code row and the token", func(t *testing.T) {
		h := newClaimsParamHarness(t)
		h.grant(t, "userinfo:name")
		h.req.Claims = `{"userinfo":{"name":{"essential":true}}}`
		if _, err := h.authz.Authorize(context.Background(), h.req); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		row := h.onlyCodeRow(t)
		if !reflect.DeepEqual(row.RequestedClaims, domain.ClaimsRequest{UserInfo: []string{"name"}}) {
			t.Fatalf("code row requested claims = %+v, want userinfo [name]", row.RequestedClaims)
		}
		if uc := h.tokenUserInfoClaims(t, domain.RoleOrgUser, row.RequestedClaims.UserInfo); len(uc) != 1 || uc[0] != "name" {
			t.Fatalf("access token userinfo_claims = %v, want [name]", uc)
		}
	})

	t.Run("role-forbidden claim never lands", func(t *testing.T) {
		h := newClaimsParamHarness(t)
		// A principal with no human role permits no identity claim, however
		// complete the consent is.
		if uc := h.tokenUserInfoClaims(t, domain.UserRole(""), []string{"name", "email"}); len(uc) != 0 {
			t.Fatalf("no-role principal: userinfo_claims = %v, want none", uc)
		}
		if uc := h.tokenUserInfoClaims(t, domain.RoleOrgUser, []string{"name", "email"}); len(uc) != 2 {
			t.Fatalf("control: org_user keeps its consented claims, got %v", uc)
		}
	})

	t.Run("unknown claim ignored, never an error", func(t *testing.T) {
		h := newClaimsParamHarness(t)
		h.grant(t, "userinfo:name")
		h.req.Claims = `{"userinfo":{"name":null,"phone_number":{"essential":true}},"introspection":{"name":null}}`
		if _, err := h.authz.Authorize(context.Background(), h.req); err != nil {
			t.Fatalf("unknown claim/member must not fail the request: %v", err)
		}
		if row := h.onlyCodeRow(t); !reflect.DeepEqual(row.RequestedClaims, domain.ClaimsRequest{UserInfo: []string{"name"}}) {
			t.Fatalf("code row = %+v, want only the emittable name", row.RequestedClaims)
		}
	})

	t.Run("malformed claims refused, redirect-safe", func(t *testing.T) {
		h := newClaimsParamHarness(t)
		h.grant(t, "userinfo:name")
		h.req.Claims = `{"userinfo":`
		if _, err := h.authz.Authorize(context.Background(), h.req); !errors.Is(err, ErrAuthorizeInvalidClaims) {
			t.Fatalf("err = %v, want ErrAuthorizeInvalidClaims", err)
		}
	})
}

// Consent coverage is scope AND claims: a stored row covering one claim does
// not cover another, and an empty request is always covered.
func TestConsentLookup_CoversClaimsLikeScopes(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	h := newClaimsParamHarness(t)
	uid := h.req.Principal.UserID
	if _, err := svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid", Claims: []string{"userinfo:name"}}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "openid", "userinfo:name")
	if !d.Covered || d.GrantedClaims != "userinfo:name" {
		t.Errorf("covered claim: %+v", d)
	}
	d, _ = svc.Lookup(context.Background(), uid, "cli-1", "", "openid", "userinfo:email")
	if d.Covered {
		t.Errorf("an unconsented claim must not be covered: %+v", d)
	}
	d, _ = svc.Lookup(context.Background(), uid, "cli-1", "", "openid")
	if !d.Covered {
		t.Errorf("no claims requested → covered by scope alone: %+v", d)
	}
}
