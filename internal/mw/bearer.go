package mw

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// SessionRevocationLookup is the narrow seam the bearer path uses to enforce
// the COMBINED session+user+org live-status check on USER-SESSION tokens —
// those carrying a non-nil SessionID, minted exclusively by
// UserTokenService.IssueForSession (interactive login / MFA / WebAuthn /
// authorization_code grant). GetSessionWithUserAndOrgStatus returns the
// session AND the user/org status in ONE query, so the Stage-1 session-
// revocation check (preserved) and the R3 user-ban/delete + org-inactive/
// deleted check are decided from a single round-trip — no extra per-request
// lookup. M2M / client-credentials / service-account / refresh-grant /
// api-resource / foreign-issuer AG tokens carry no session_id (nil SessionID)
// and never trigger a lookup. See
// docs/audit/auth-surface/user-vs-m2m-token-discrimination.md and
// session-binding-blast-radius.md for the design.
type SessionRevocationLookup interface {
	GetSessionWithUserAndOrgStatus(ctx context.Context, id uuid.UUID) (*domain.SessionValidationInfo, error)
}

// BearerRevocationLookup is the narrow seam the bearer path uses to enforce
// RFC 7009 per-token (jti) revocation on EVERY bearer token — user-session
// AND M2M / client-credentials / service-account — keyed by the token's
// `jti`. *service.TokenRevocationService satisfies it via IsRevoked. Unlike
// the session gate, this does NOT depend on principal.SessionID: an M2M token
// carries a jti but no session, and a successful RFC 7009 revocation of it
// MUST take effect. The check is FAIL-CLOSED — a revoked jti OR a store error
// both reject — so a transient revocation-store outage cannot admit a token
// that may have been revoked.
type BearerRevocationLookup interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// sessionSubjectResolver is the OSS implementation of the A-4 Phase 6a
// pkg/oidc.SubjectResolver seam: it keys principal liveness on the SESSION,
// wrapping the same SessionRevocationLookup single-round-trip query the
// bearer path has always used, and applying the same combined
// session+user+org verdict (CanBeUsedForAuth). FAIL-CLOSED at every step: an
// unparsable SessionID, a lookup error, or a nil info all resolve to false —
// this resolver never admits a principal whose liveness it cannot establish.
// (CE's resolver will key on the SUBJECT instead — that policy difference is
// exactly why the seam carries both fields and owns only the verdict.)
type sessionSubjectResolver struct {
	sessions SessionRevocationLookup
}

var _ oidc.SubjectResolver = sessionSubjectResolver{}

func (r sessionSubjectResolver) ResolveSubject(ctx context.Context, ref oidc.PrincipalRef) (bool, error) {
	sid, err := uuid.Parse(ref.SessionID)
	if err != nil {
		// A session-gated principal with an unparsable session id cannot be
		// proven live. (Unreachable from BearerPrincipal, which stringifies
		// a canonical uuid.UUID — but the seam is public-shaped, so the
		// resolver defends itself.)
		return false, err
	}
	info, err := r.sessions.GetSessionWithUserAndOrgStatus(ctx, sid)
	if err != nil {
		return false, err
	}
	if info == nil {
		return false, nil
	}
	ok, _ := info.CanBeUsedForAuth(time.Now().UTC())
	return ok, nil
}

// BearerOption customises BearerPrincipal without disturbing its four
// positional parameters (all existing call sites compile unchanged).
type BearerOption func(*bearerOptions)

type bearerOptions struct {
	resolver    oidc.SubjectResolver
	resolverSet bool
}

// WithSubjectResolver overrides the pkg/oidc.SubjectResolver the bearer path
// consults for the session+user+org liveness verdict on user-session tokens.
// Passing nil disables the gate. Intended for tests; production wiring uses
// the default resolver derived from `sessions`.
func WithSubjectResolver(r oidc.SubjectResolver) BearerOption {
	return func(o *bearerOptions) {
		o.resolver = r
		o.resolverSet = true
	}
}

// TokenVerifier is the seam between the bearer-token populator
// middleware and any concrete JWT verification implementation. The
// default OSS-shipped implementation lives in
// internal/auth/jwt_verifier.go and verifies tokens against the
// active signing keys in the OSS KeyRepository.
//
// Verifiers MUST treat the token parameter as untrusted and MUST
// NOT echo it back in any error path. Implementations also MUST
// enforce the Identuum no-RS256-issuance policy (verification of
// locally-issued tokens accepts EdDSA and ES256 only).
type TokenVerifier interface {
	VerifyBearerToken(ctx context.Context, token string) (*domain.Principal, error)
}

// BearerPrincipal returns a middleware that reads
// Authorization: Bearer <jwt>, calls verifier.VerifyBearerToken, and
// on success plants the resulting principal into the gin.Context.
// Downstream guards (RequireAuthenticated / RequireSiteAdmin /
// RequireScopesAny) then make the authorization decision.
//
// Behaviour:
//
//   - No Authorization header        → c.Next() (downstream guards
//     see no principal and 401).
//   - Authorization with a Bearer scheme in ANY casing → treated as a
//     Bearer presentation (RFC 6750 §2.1; CONF-8).
//   - Authorization with wrong scheme → c.Next() with NO principal, so
//     the route's own guard decides (CONF-1, option A). A non-Bearer
//     scheme is another authenticator's credential — notably the
//     client_secret_basic that discovery advertises on the token,
//     revocation and introspection endpoints, which this middleware
//     fronts (one mount, via mountBearerAuth in internal/api/router.go). Protected routes still 401; the refusal simply comes
//     from the downstream guard rather than from here.
//   - Empty Bearer payload            → 401.
//   - verifier returns error          → 401, no detail surfaced.
//   - verifier returns nil principal  → 401 (defence in depth).
//   - verifier returns principal      → SetPrincipal + c.Next().
//
// The token string is never written to logs, response bodies, or
// error metadata. Verifier errors are deliberately swallowed at
// this layer because the caller already knows their token failed —
// surfacing the reason would help attackers tune brute-force
// attempts.
//
// Session-revocation enforcement (Stage-1): after cryptographic
// verification succeeds, a USER-SESSION token (principal.SessionID
// non-nil) is additionally checked against the live session store via
// `sessions`. If the session is missing, unusable (revoked / expired /
// invalid), OR the lookup itself errors, the request is rejected — the
// lookup is FAIL-CLOSED so a transient store outage cannot let a revoked
// token through. Tokens with a nil SessionID (M2M / client / refresh /
// api-resource) are EXEMPT: no lookup, no rejection on this basis. When
// `sessions` is nil (no session store wired, e.g. the no-DB scaffold)
// the check is skipped. The discriminator is `principal.SessionID`
// presence only.
func BearerPrincipal(report *lifecycle.StartupReport, verifier TokenVerifier, sessions SessionRevocationLookup, revocations BearerRevocationLookup, opts ...BearerOption) gin.HandlerFunc {
	// A-4 Phase 6a: the session+user+org liveness VERDICT now runs behind
	// the pkg/oidc.SubjectResolver seam. The default resolver wraps the
	// same `sessions` lookup as before; sessions == nil means no resolver
	// and the gate is skipped exactly as today. The POLICY — which tokens
	// get gated (the M2M SessionID discriminator below) — deliberately
	// stays here, not in the seam.
	var o bearerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	resolver := o.resolver
	if !o.resolverSet {
		resolver = NewSessionSubjectResolver(sessions)
	}
	if verifier == nil {
		// P-018 NOT-SERVING-JUST-ALERTING: a bearer populator with no
		// verifier cannot authenticate anyone. Previously this panicked at
		// construction time, killing the process. Instead, record a fatal
		// startup fault (the runtime enters NOT-SERVING; the health probe
		// surfaces it) and return a FAIL-CLOSED populator that admits NO
		// principal — every protected route then rejects (401) while public
		// routes are unaffected. The fault reason is secret-free. report is
		// nil-safe.
		report.Fatal(
			"bearer-auth",
			"bearer authentication unavailable: token verifier not wired",
		)
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.Next()
			return
		}
		// RFC 6750 §2.1 makes the auth-scheme case-INSENSITIVE, and the
		// handlers that parse this header themselves already treat it that way
		// (internal/handlers: userinfo.go readUserinfoBearerToken,
		// auth_sessions.go extractValidateToken, dcr.go extractBearerToken).
		// Matching case-sensitively here made `bearer <token>` and
		// `Bearer <token>` take DIFFERENT paths through one request: the
		// capitalised form was gated by this middleware — signature, jti
		// revocation, session/user/org liveness — while the lowercase form
		// fell through unpopulated and was then picked up downstream by a
		// weaker gate set. A banned user's token was refused as `Bearer` and
		// admitted as `bearer` (CONF-8). EqualFold makes the populator agree
		// with its own handlers.
		const prefix = "Bearer "
		if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
			// CONF-1 (OWNER DECISION, option A): a non-Bearer scheme is NOT
			// this middleware's credential. Pass it through WITHOUT planting a
			// principal and let the route's own guard decide.
			//
			// This middleware is mounted globally by mountBearerAuth (internal/api/router.go,
			// called from RegisterOSSRoutes) ahead of the OAuth client-auth
			// routes — revocation and token. While this branch 401'd, an `Authorization: Basic`
			// presentation was eaten here before mw.RequireOAuthClient could
			// see it — so client_secret_basic, which discovery ADVERTISES on
			// the token, revocation and introspection endpoints, could not be
			// used at all. Found by the cross-engine conformance suite.
			//
			// Security is unchanged for principal-protected routes: no
			// principal is set, so RequireAuthenticated / RequireSiteAdmin /
			// RequireScopesAny still 401 exactly as before — only the layer
			// that refuses moves. Pinned by
			// TestBearerPrincipal_WrongSchemePassesToDownstreamGuard.
			c.Next()
			return
		}
		// Slice by LENGTH, not TrimPrefix: TrimPrefix is case-SENSITIVE, so on
		// a non-canonical casing it is a no-op and the whole header — scheme
		// included — would be handed to the verifier. That fails closed (the
		// verifier rejects it) but blanket-401s a legitimate `bearer <token>`,
		// which is precisely the RFC 6750 conformance this change exists to
		// deliver. The scheme match above is case-insensitive; the extraction
		// must be too. This is what all three handler-side extractors do.
		token := strings.TrimSpace(header[len(prefix):])
		if token == "" {
			RespondUnauthenticatedReason(c, ReasonMissingCredential)
			return
		}
		principal, err := verifier.VerifyBearerToken(c.Request.Context(), token)
		if err != nil || principal == nil {
			// AUTH-503: a key-STORE failure inside the verifier is not a token
			// verdict — the token was never judged. 503 + ERROR log; the
			// refusal itself is unchanged (nothing is admitted).
			if domain.IsAuthStoreUnavailable(err) {
				RespondAuthStoreUnavailable(c, "bearer.verify", err)
				return
			}
			RespondUnauthenticatedReason(c, ReasonTokenInvalid)
			return
		}
		// RFC 7009 per-token revocation (P0-6), enforced for EVERY bearer
		// token regardless of SessionID — so M2M / client-credentials /
		// service-account tokens (which carry a jti but no session) honor
		// revocation. FAIL-CLOSED: a revoked jti OR a revocation-store error
		// both reject, so a transient store outage cannot admit a token that
		// may have been revoked. A token with no jti cannot be individually
		// revoked by this store and is left to the other gates.
		if revocations != nil && principal.TokenID != "" {
			revoked, revErr := revocations.IsRevoked(c.Request.Context(), principal.TokenID)
			if revErr != nil {
				// AUTH-503: still fail-CLOSED (the token is refused) but as a
				// 503 with its ERROR log — the revocation STORE erred, the
				// token was not judged revoked. Before this slice this was the
				// same unlogged 401 as a genuinely revoked token.
				RespondAuthStoreUnavailable(c, "bearer.revocation", revErr)
				return
			}
			if revoked {
				RespondUnauthenticatedReason(c, ReasonTokenRevoked)
				return
			}
		}
		// User-session tokens (non-nil SessionID) must honor server-side
		// revocation AND live user/org status; M2M / client tokens (nil
		// SessionID) are exempt — they are not user sessions, so no
		// user/org gate applies. The discriminator stays HERE (policy);
		// the resolver owns only the verdict (A-4 Phase 6a). The combined
		// session+user+org check behind the seam is unchanged: session
		// usability FIRST (valid / not revoked / not expired — the exact
		// Stage-1 revocation check, preserved), THEN banned/deleted user,
		// THEN inactive/deleted org, all from the single-round-trip lookup
		// (R3 defense-in-depth, mirroring the ancestor's CanBeUsedForAuth).
		// FAIL-CLOSED: a resolver error rejects exactly like a false
		// verdict — a possibly-revoked principal is never admitted because
		// the check could not complete.
		// Subject is principal.Sub — the `sub` claim VERBATIM, as
		// pkg/oidc.PrincipalRef.Subject's contract requires. It used to be
		// principal.UserID.String(), which is a different value: UserID is
		// uuid.Nil for a non-uuid sub and is overwritten by a `user_id` claim,
		// so the two doors could ask a subject-keyed resolver about DIFFERENT
		// principals — userinfo about `sub`, this path about a uuid (CONF-11).
		//
		// There is deliberately NO fallback to UserID.String() when Sub is
		// empty, and empty IS reachable: `sub` is not required on this path
		// (VerifyBearerToken passes jwtpolicy.Required{Expiration: true} only,
		// so monolith tokens may carry user_id instead). A subject-keyed
		// resolver asked about "" finds nobody and denies. That is the right
		// outcome: substituting a uuid for a missing subject is a GUESS, and a
		// guess that collides with some other principal's subject resolves the
		// wrong principal's liveness — a silently wrong verdict, which is worse
		// than a refusal. Fail closed. (OSS's own resolver is session-keyed and
		// never reads Subject, so this changes nothing for it today.)
		if resolver != nil && principal.SessionID != (uuid.UUID{}) {
			ok, resErr := resolver.ResolveSubject(c.Request.Context(), oidc.PrincipalRef{
				Subject:   principal.Sub,
				SessionID: principal.SessionID.String(),
			})
			if resErr != nil {
				// AUTH-503: the liveness STORE erred (the resolver returns an
				// error only for infrastructure; "no such session" is ok=false).
				// Fail closed as 503 with its ERROR log, not as a verdict.
				RespondAuthStoreUnavailable(c, "bearer.liveness", resErr)
				return
			}
			if !ok {
				RespondUnauthenticatedReason(c, ReasonSessionNotLive)
				return
			}
		}
		SetPrincipal(c, principal)
		c.Next()
	}
}

// NewSessionSubjectResolver builds the DEFAULT use-time liveness resolver over
// a session lookup: the same verdict BearerPrincipal applies on the header
// path. Returns nil when sessions is nil, which every consumer reads as "no
// gate", preserving today's behaviour for callers that wire no lookup.
//
// Exported so the userinfo handler can reuse the EXISTING verdict rather than
// construct a second, divergent one (CONF-10). This is the ONE construction
// site for that resolver; BearerPrincipal's default calls it too.
func NewSessionSubjectResolver(sessions SessionRevocationLookup) oidc.SubjectResolver {
	if sessions == nil {
		return nil
	}
	return sessionSubjectResolver{sessions: sessions}
}
