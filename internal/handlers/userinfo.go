package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
	"github.com/identuum/identuum-idp-oss/types"
)

// UserinfoHandlerDeps wires the OIDC Core §5.3 userinfo endpoint
// for the OSS build.
//
// IntrospectionService is required: it provides the
// verify-and-revocation-check pipeline. The handler reads the
// raw bearer token, runs it through
// IntrospectionService.IntrospectActiveClaims, and projects the
// result into types.OIDCUserInfo.
//
// Audit defaults to NoopService.
type UserinfoHandlerDeps struct {
	IntrospectionService *service.IntrospectionService
	Audit                audit.Service

	// SubjectResolver, when non-nil, applies the use-time liveness verdict —
	// session not revoked, user not banned/deleted, organization still active.
	// Build it with mw.NewSessionSubjectResolver so this path reuses the SAME
	// verdict the bearer middleware applies, never a second one. Nil skips the
	// gate (today's behaviour for callers that wire no session lookup).
	SubjectResolver oidc.SubjectResolver

	// UserLookup, when non-nil, backs the OIDC `profile`-scope claims:
	// a human token whose scope grants "profile" gets `name` from the
	// user record (the access token deliberately does not carry it).
	// Nil keeps the pre-THE-PKCE-DECISION projection (no profile
	// claims), so existing compositions are unchanged.
	UserLookup UserByIDLookup

	// ProfileLookup, when non-nil, backs the remaining OIDC §5.1 profile
	// claims (given_name … locale) from the user's optional profile row
	// (THE-PROFILE-CLAIMS). Nil = only name/updated_at from the user row.
	ProfileLookup ProfileByUserLookup
}

// ProfileByUserLookup is the narrow read seam for the optional profile row.
// Satisfied by *service.UserProfileService.
type ProfileByUserLookup interface {
	Get(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error)
}

// RegisterUserinfoRoutes mounts
//
//	GET  /api/v1/oidc/userinfo
//	POST /api/v1/oidc/userinfo
//
// onto router. OIDC Core §5.3.1 allows both GET (with bearer in
// Authorization header) and POST (form-encoded access_token).
// The route registers ONLY when IntrospectionService is non-nil —
// without it there is no safe way to verify the bearer token.
func RegisterUserinfoRoutes(router gin.IRouter, deps UserinfoHandlerDeps) {
	if deps.IntrospectionService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/oidc")

	// docgen:endpoint
	// docgen:surface=oidc
	// docgen:method=GET
	// docgen:path=/api/v1/oidc/userinfo
	// docgen:summary=OIDC Core §5.3.1 userinfo (GET form).
	// docgen:tier=oss
	// docgen:auth=bearer
	g.GET("/userinfo", HandleUserinfo(deps))

	// docgen:endpoint
	// docgen:surface=oidc
	// docgen:method=POST
	// docgen:path=/api/v1/oidc/userinfo
	// docgen:summary=OIDC Core §5.3.1 userinfo (POST form — accepts the bearer access token in either the Authorization header or the access_token form parameter).
	// docgen:tier=oss
	// docgen:auth=bearer
	g.POST("/userinfo", HandleUserinfo(deps))
}

// HandleUserinfo implements OIDC Core §5.3.1 — userinfo response.
// Behavior:
//
//   - Missing bearer or invalid/revoked/expired token → 401 with
//     WWW-Authenticate: Bearer + {"error":"invalid_token"}.
//   - On success: 200 with the OIDC standard claims projection.
//     `sub` is REQUIRED per §5.3.2; `email`, `organization_id`,
//     and `role` are echoed only when the token's claims carry
//     them (the principal model defines what may be there);
//     `name` is looked up from the user record for human subjects
//     when a UserLookup is wired.
//
// The raw access token NEVER appears in the response or in audit
// metadata. The jti claim is consumed for the revocation check
// but is NOT echoed in the response.
func HandleUserinfo(deps UserinfoHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := readUserinfoBearerToken(c)
		if token == "" {
			respondUserinfoUnauthorized(c)
			return
		}
		claims, ok := deps.IntrospectionService.IntrospectActiveClaims(c.Request.Context(), token)
		if !ok || claims == nil {
			respondUserinfoUnauthorized(c)
			return
		}
		// CONF-10 — use-time liveness, on BOTH doors.
		//
		// BearerPrincipal gates the Authorization-header path fully, but with
		// NO header it calls c.Next() at once and readUserinfoBearerToken then
		// takes the token from the `access_token` FORM field (RFC 6750 §2.2
		// permits that). That door reached IntrospectActiveClaims alone —
		// signature + jti, NO liveness — so a BANNED user was refused as a
		// header and admitted as a form field.
		//
		// The check runs UNCONDITIONALLY, not only on the form path, and the
		// resulting second lookup on the header path is DELIBERATE: it costs
		// one query, and it means this handler is safe on its own terms rather
		// than safe only while it happens to sit behind the middleware. A
		// guard that depends on its mounting is one refactor from being gone.
		//
		// Fail-closed per the seam contract: a non-nil error is treated exactly
		// like not-live. A token with NO session (uuid.Nil — client-credentials
		// or service-account, i.e. M2M) is exempt, because there is no session
		// to check; that is the same discriminator the middleware applies.
		if deps.SubjectResolver != nil && claims.SessionID != uuid.Nil {
			live, err := deps.SubjectResolver.ResolveSubject(c.Request.Context(), oidc.PrincipalRef{
				Subject:   claims.Sub,
				SessionID: claims.SessionID.String(),
			})
			if err != nil || !live {
				respondUserinfoUnauthorized(c)
				return
			}
		}

		// Build the OIDC userinfo response. sub is mandatory.
		// Service-account tokens MUST NOT carry email/name claims —
		// a non-human identity has no inbox and no display name to
		// expose via userinfo. The presence of actor_type =
		// "service_account" is the load-bearing signal.
		isServiceAccount := claims.ActorType == service.ActorTypeServiceAccount
		out := types.OIDCUserInfo{
			Sub: userinfoSub(claims),
		}
		// THE-CONSENTED-SCOPE: profile claims are released under the scope
		// the token CARRIES (OIDC Core §5.4) — `email`/`email_verified`
		// under "email", `name` under "profile" — for human subjects only.
		// The access token's `scope` claim is the consented ∩ role-permitted
		// set for client-bound tokens and the role-derived set for login
		// sessions; neither grants identity claims it does not name, so a
		// session token gets `sub` (+ org/role) and nothing personal.
		// Conformance-measured (EnsureUserInfoDoesNotContainName): name
		// landed without profile. Lookup failure degrades to the claim
		// being absent — voluntary claims are never worth a 500.
		grants := userinfoScopeSet(claims.Scope)
		// THE-CLAIMS-PARAMETER (OIDC Core §5.5): an individually requested,
		// consented, role-permitted claim rides on the token as
		// userinfo_claims and releases the same way a scope would.
		requested := userinfoScopeSet(strings.Join(claims.UserInfoClaims, " "))
		releaseEmail := grants[domain.ScopeEmail] || requested["email"] || requested["email_verified"]
		// THE-PROFILE-CLAIMS: the profile family is released whole under the
		// profile scope, or claim-by-claim under the claims parameter.
		// THE-ADDRESS-PHONE-CLAIMS: the same shape for scope=address
		// (the structured address) and scope=phone (phone_number +
		// phone_number_verified), or claim-by-claim under the claims
		// parameter.
		var wantProfile []string
		if grants[domain.ScopeProfile] {
			wantProfile = append(wantProfile, domain.ProfileClaimNames...)
		}
		if grants[domain.ScopeAddress] {
			wantProfile = append(wantProfile, domain.AddressClaimNames...)
		}
		if grants[domain.ScopePhone] {
			wantProfile = append(wantProfile, domain.PhoneClaimNames...)
		}
		for _, n := range claims.UserInfoClaims {
			if domain.IsProfileClaim(n) || domain.IsAddressClaim(n) || domain.IsPhoneClaim(n) {
				wantProfile = append(wantProfile, n)
			}
		}
		var user *domain.User
		if !isServiceAccount && deps.UserLookup != nil && claims.UserID != uuid.Nil && (releaseEmail || len(wantProfile) > 0) {
			if u, uerr := deps.UserLookup.GetByID(c.Request.Context(), claims.UserID); uerr == nil {
				user = u
			}
		}
		if !isServiceAccount && releaseEmail {
			out.Email = claims.Email
			if user != nil {
				verified := user.EmailVerified
				out.EmailVerified = &verified
			}
		}
		if !isServiceAccount && len(wantProfile) > 0 && user != nil {
			var profile *domain.UserProfile
			if deps.ProfileLookup != nil {
				if p, perr := deps.ProfileLookup.Get(c.Request.Context(), claims.UserID); perr == nil {
					profile = p
				}
			}
			applyProfileClaims(&out, domain.ProfileClaims(user, profile, wantProfile))
		}
		if claims.OrgID != uuid.Nil {
			out.OrganizationID = claims.OrgID.String()
		}
		if claims.Role != "" {
			out.Role = claims.Role
		}
		if out.Sub == "" {
			// IntrospectActiveClaims already guards against the
			// no-subject case, but if every identifier was zero we
			// still won't render an OIDC-compliant body.
			respondUserinfoUnauthorized(c)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "oidc_userinfo.served",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"sub_kind": userinfoSubKind(claims),
			},
		})
		c.JSON(http.StatusOK, out)
	}
}

// applyProfileClaims copies the truthfully-emittable profile claims
// (domain.ProfileClaims) onto the userinfo projection. Absent keys stay
// absent — the struct's omitempty tags never render a placeholder.
func applyProfileClaims(out *types.OIDCUserInfo, claims map[string]any) {
	str := func(k string) string {
		if v, ok := claims[k].(string); ok {
			return v
		}
		return ""
	}
	out.Name = str("name")
	out.GivenName = str("given_name")
	out.FamilyName = str("family_name")
	out.MiddleName = str("middle_name")
	out.Nickname = str("nickname")
	out.PreferredUsername = str("preferred_username")
	out.Profile = str("profile")
	out.Picture = str("picture")
	out.Website = str("website")
	out.Gender = str("gender")
	out.Birthdate = str("birthdate")
	out.Zoneinfo = str("zoneinfo")
	out.Locale = str("locale")
	if v, ok := claims["updated_at"].(int64); ok {
		out.UpdatedAt = v
	}
	// THE-ADDRESS-PHONE-CLAIMS: phone_number (+ phone_number_verified, which
	// domain.ProfileClaims emits only alongside it, always false) and the
	// structured address (set members only; absent when none).
	out.PhoneNumber = str(domain.ClaimPhoneNumber)
	if v, ok := claims[domain.ClaimPhoneNumberVerified].(bool); ok && out.PhoneNumber != "" {
		verified := v
		out.PhoneNumberVerified = &verified
	}
	if addr, ok := claims[domain.ClaimAddress].(map[string]any); ok && len(addr) > 0 {
		a := func(k string) string {
			if v, ok := addr[k].(string); ok {
				return v
			}
			return ""
		}
		out.Address = &types.OIDCAddress{
			Formatted: a("formatted"), StreetAddress: a("street_address"), Locality: a("locality"),
			Region: a("region"), PostalCode: a("postal_code"), Country: a("country"),
		}
	}
}

// userinfoScopeSet splits the token's space-separated scope claim into a
// membership set.
func userinfoScopeSet(scope string) map[string]bool {
	out := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		out[s] = true
	}
	return out
}

// userinfoSub returns the value to use for the `sub` field. Prefer
// the explicit Sub claim, then the user UUID (when present), then
// the client_id.
func userinfoSub(claims *service.IntrospectionClaims) string {
	if claims == nil {
		return ""
	}
	if strings.TrimSpace(claims.Sub) != "" {
		return claims.Sub
	}
	if claims.UserID != uuid.Nil {
		return claims.UserID.String()
	}
	return claims.ClientID
}

// userinfoSubKind classifies the principal as "user" /
// "service_account" / "client" for the audit projection. It
// MUST NOT reveal the raw sub value. The actor_type marker on
// the access token wins when present; otherwise we fall back
// to UserID / ClientID heuristics.
func userinfoSubKind(claims *service.IntrospectionClaims) string {
	if claims.ActorType == service.ActorTypeServiceAccount {
		return service.ActorTypeServiceAccount
	}
	if claims.UserID != uuid.Nil {
		return "user"
	}
	if claims.ClientID != "" {
		return "client"
	}
	return "unknown"
}

// readUserinfoBearerToken extracts the access token from either
// `Authorization: Bearer ...` or the `access_token` form field
// per OIDC Core §5.3.1 (RFC 6750). Whitespace-only values are
// treated as empty.
func readUserinfoBearerToken(c *gin.Context) string {
	authz := c.GetHeader("Authorization")
	if authz != "" {
		const prefix = "Bearer "
		if len(authz) > len(prefix) && strings.EqualFold(authz[:len(prefix)], prefix) {
			return strings.TrimSpace(authz[len(prefix):])
		}
	}
	return strings.TrimSpace(c.PostForm("access_token"))
}

// respondUserinfoUnauthorized emits the canonical RFC 6750 §3.1
// 401 + WWW-Authenticate: Bearer envelope. The body is a small
// JSON object so curl-like clients can parse it.
func respondUserinfoUnauthorized(c *gin.Context) {
	c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": "invalid_token",
	})
}
