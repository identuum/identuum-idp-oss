package mw

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OAuthClientAuthenticator is the seam the middleware consumes.
// *service.OAuthClientAuthService satisfies it; CE composition
// can plug in alternative implementations without changing the
// middleware contract.
type OAuthClientAuthenticator interface {
	// authMethod is the client-auth method the caller OBSERVED on the wire —
	// "client_secret_basic" (HTTP Basic) or "client_secret_post" (form body).
	// The authenticator MUST require the resolved client's registered method
	// to match EXACTLY, so a private_key_jwt or public client cannot be
	// downgraded to secret auth and basic/post are not interchangeable (P0-7).
	Authenticate(ctx context.Context, clientID, clientSecret, authMethod string) (*service.AuthenticatedClient, error)
}

// OAuthClientAssertionAuthenticator is the optional extension
// seam for clients authenticating with `client_assertion` +
// `client_assertion_type` form fields (private_key_jwt). The
// middleware checks for this method at request time and routes
// JWT-bearing requests through it; legacy clients posting
// `client_id` + `client_secret` continue to flow through
// Authenticate.
//
// *service.OAuthClientAuthService satisfies this when constructed
// with WithAssertionValidator.
type OAuthClientAssertionAuthenticator interface {
	AuthenticateAssertion(ctx context.Context, clientID, assertionJWT string) (*service.AuthenticatedClient, error)
}

// oauthClientCtxKey is the gin.Context key under which the
// successfully authenticated client is stored. Unexported so
// callers go through AuthenticatedClientFromContext.
const oauthClientCtxKey = "identuum-oss-oauth-client"

// SetAuthenticatedClientForTest plants a client in the request
// context. Test-only helper; production code goes through
// RequireOAuthClient.
func SetAuthenticatedClientForTest(c *gin.Context, ac *service.AuthenticatedClient) {
	c.Set(oauthClientCtxKey, ac)
}

// AuthenticatedClientFromContext returns the client and a
// presence flag.
func AuthenticatedClientFromContext(c *gin.Context) (*service.AuthenticatedClient, bool) {
	v, ok := c.Get(oauthClientCtxKey)
	if !ok {
		return nil, false
	}
	ac, ok := v.(*service.AuthenticatedClient)
	if !ok || ac == nil {
		return nil, false
	}
	return ac, true
}

// RequireOAuthClient is the OSS implementation of RFC 7662 §2.1 /
// RFC 7009 §2.1 client authentication for the introspection /
// revocation endpoints. It accepts:
//
//   - client_secret_basic — `Authorization: Basic <base64>`
//   - client_secret_post  — `client_id` + `client_secret` form fields
//
// Behavior:
//
//   - Missing credentials → 401 with
//     `WWW-Authenticate: Basic realm="oauth-client"` and
//     `{"error":"invalid_client"}` (RFC 6749 §5.2).
//   - Wrong credentials   → same 401 shape. The wire response
//     does not distinguish "unknown client_id" from "wrong
//     secret" — that distinction is an enumeration oracle.
//   - Empty secret on a confidential client → 401 (the underlying
//     service rejects empty secrets).
//   - Success: the authenticated client is planted in the gin
//     context via SetAuthenticatedClientForTest's exported key
//     and the chain continues.
//
// nil authenticator is a programmer error: the middleware panics
// rather than silently allowing every request through. Operators
// that want to disable client auth on a route should not mount
// this middleware at all.
//
// The raw clientSecret is NEVER written to logs, error messages,
// or response bodies. The 401 body is a fixed
// `{"error":"invalid_client"}` envelope with no contextual
// detail.
func RequireOAuthClient(report *lifecycle.StartupReport, authn OAuthClientAuthenticator) gin.HandlerFunc {
	if authn == nil {
		// P-018: an OAuth-client authenticator that is not wired cannot
		// authenticate any client on the token/introspection/revocation
		// path — security-critical. FATAL. Record the fault and return a
		// fail-closed middleware that rejects every request with
		// invalid_client, instead of panicking.
		report.Fatal(
			"RequireOAuthClient",
			"mw: RequireOAuthClient requires a non-nil OAuthClientAuthenticator",
		)
		return func(c *gin.Context) { respondInvalidClient(c) }
	}
	assertionAuthn, _ := authn.(OAuthClientAssertionAuthenticator)
	return func(c *gin.Context) {
		// JWT-assertion path (private_key_jwt). RFC 7521 / RFC 7523
		// / OIDC Core §9. When a request carries the canonical
		// `client_assertion_type` URN AND a non-empty
		// `client_assertion`, the assertion path takes priority over
		// Basic / Post — even if `client_secret` is also present,
		// passing the assertion implies the caller wants assertion
		// auth. The assertion path MUST NOT fall back to secret-auth
		// on failure.
		assertionType := c.PostForm("client_assertion_type")
		assertion := c.PostForm("client_assertion")
		if assertionType == service.ClientAssertionTypeJWTBearer && assertion != "" {
			if assertionAuthn == nil {
				respondInvalidClient(c)
				return
			}
			// client_id is optional on the wire when the JWT iss/sub
			// carry the identity, but the validator needs a concrete
			// lookup key. We extract it from the form value when
			// present and fall back to an empty string otherwise;
			// AuthenticateAssertion rejects empty client_id.
			clientID := c.PostForm("client_id")
			if clientID == "" {
				// RFC 7521 §4.2 allows the assertion's iss to be the
				// client identifier when client_id is omitted. We
				// require the form value here to keep the OSS path
				// simple — the brief explicitly calls for "client_id
				// where monolith requires it".
				respondInvalidClient(c)
				return
			}
			ac, err := assertionAuthn.AuthenticateAssertion(c.Request.Context(), clientID, assertion)
			if err != nil || ac == nil {
				// AUTH-503: a client-STORE failure is not an invalid_client verdict.
				if domain.IsAuthStoreUnavailable(err) {
					RespondAuthStoreUnavailable(c, "client-auth.assertion", err)
					return
				}
				respondInvalidClient(c)
				return
			}
			c.Set(oauthClientCtxKey, ac)
			c.Next()
			return
		}

		// Basic / Post (client_secret_basic / client_secret_post). The
		// OBSERVED method is passed through so the authenticator can require
		// the client's EXACTLY-registered method (P0-7): Basic and Post are
		// not interchangeable, and a private_key_jwt / public client cannot
		// authenticate with a secret at all.
		clientID, clientSecret, hasBasic := c.Request.BasicAuth()
		observedMethod := service.ClientAuthMethodBasic
		if !hasBasic {
			clientID = c.PostForm("client_id")
			clientSecret = c.PostForm("client_secret")
			observedMethod = service.ClientAuthMethodPost
		}
		if clientID == "" || clientSecret == "" {
			respondInvalidClient(c)
			return
		}
		ac, err := authn.Authenticate(c.Request.Context(), clientID, clientSecret, observedMethod)
		if err != nil || ac == nil {
			// AUTH-503: a client-STORE failure is not an invalid_client verdict.
			if domain.IsAuthStoreUnavailable(err) {
				RespondAuthStoreUnavailable(c, "client-auth.secret", err)
				return
			}
			respondInvalidClient(c)
			return
		}
		c.Set(oauthClientCtxKey, ac)
		c.Next()
	}
}

func respondInvalidClient(c *gin.Context) {
	c.Header("WWW-Authenticate", `Basic realm="oauth-client"`)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": "invalid_client",
	})
}
