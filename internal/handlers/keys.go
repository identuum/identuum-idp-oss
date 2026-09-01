// Package handlers hosts the OSS-safe HTTP handlers that the OSS
// Gin scaffold registers. As of this slice, only the signing-keys
// admin group is here — additional groups will land in subsequent
// handler-extraction slices.
//
// SCOPE / AUTH STATUS
//
// As of the OSS auth middleware seam slice, the keys route group
// is guarded by mw.RequireSiteAdmin(). The OSS module does NOT yet
// ship the upstream layer that populates the principal — real
// session/OIDC validation is still future work. Operators wiring
// --gin-serve directly will see every keys request 401 by default
// because no principal is in the context. To exercise the keys
// surface today, mount an upstream layer that calls
// mw.SetPrincipal(c, p) (CE wiring, a reverse proxy that maps an
// mTLS identity, or mw.InjectPrincipalForTest in tests).
//
// This means --gin-serve is still NOT production-deployable as a
// standalone OSS binary; but the route group now refuses requests
// instead of serving them open.
package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// KeysHandlerDeps is the dependency bundle the OSS keys handler
// group requires. Pass these in from the bootstrap layer.
type KeysHandlerDeps struct {
	// KeyService is the OSS key-management service. Required.
	KeyService *service.KeyService

	// Audit is the audit.Service seam. nil is replaced by
	// audit.NoopService{} so handlers never have to nil-check.
	Audit audit.Service

	// StartupReport receives a fatal fault if KeyService is not wired —
	// instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterKeysRoutes wires the signing-keys admin group onto the
// given Gin router. Registers under "/api/v1/keys".
//
// Endpoints (all currently UNAUTHENTICATED — see the package doc):
//
//	GET    /api/v1/keys              — list signing keys (public fields only)
//	POST   /api/v1/keys/generate     — generate a new EdDSA or ES256 key
//	POST   /api/v1/keys/rotate       — rotate old_kid → new_kid
//	POST   /api/v1/keys/deprecate    — deprecate by kid
//	DELETE /api/v1/keys/expired      — purge deprecated-past-expiry rows
//	POST   /api/v1/keys/reload       — 501 (KeyManager not in OSS yet)
//
// If deps.KeyService is nil, the function panics — wiring a keys
// handler group without a backing service is a bootstrap bug.
func RegisterKeysRoutes(router gin.IRouter, deps KeysHandlerDeps) {
	if deps.KeyService == nil {
		// P-018: a signing-key admin surface with no KeyService cannot
		// answer any request. FATAL (signing-key control is on the
		// security-critical path). Record the fault and mount a uniform
		// service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"keys-routes",
			"signing-key admin surface unavailable: KeyService not wired",
		)
		g := router.Group("/api/v1/keys")
		g.GET("", serviceMissingFallback("keys"))
		g.POST("/generate", serviceMissingFallback("keys"))
		g.POST("/rotate", serviceMissingFallback("keys"))
		g.POST("/deprecate", serviceMissingFallback("keys"))
		g.DELETE("/expired", serviceMissingFallback("keys"))
		g.POST("/reload", serviceMissingFallback("keys"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// All keys routes require an authenticated site-admin principal.
	// Population of the principal (real session/OIDC parsing) is a
	// future slice; until then the guard relies on whatever upstream
	// component (CE wiring, reverse proxy, test helper) called
	// mw.SetPrincipal.
	keys := router.Group("/api/v1/keys")
	keys.Use(mw.RequireSiteAdmin())

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=GET
	// docgen:path=/api/v1/keys
	// docgen:summary=List signing keys (safe projection — never exposes private key material).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:response=oss.handlers.safeKey
	keys.GET("", HandleListSigningKeys(deps))

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=POST
	// docgen:path=/api/v1/keys/generate
	// docgen:summary=Generate a new signing key and persist it (private key never returned).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:response=oss.handlers.safeKey
	// docgen:status=201
	keys.POST("/generate", HandleGenerateSigningKey(deps))

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=POST
	// docgen:path=/api/v1/keys/rotate
	// docgen:summary=Rotate signing keys (new active key + retire previous).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:response=oss.handlers.safeKey
	keys.POST("/rotate", HandleRotateSigningKey(deps))

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=POST
	// docgen:path=/api/v1/keys/deprecate
	// docgen:summary=Deprecate a signing key by kid.
	// docgen:tier=oss
	// docgen:auth=site_admin
	keys.POST("/deprecate", HandleDeprecateSigningKey(deps))

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=DELETE
	// docgen:path=/api/v1/keys/expired
	// docgen:summary=Purge deprecated-past-expiry signing key rows.
	// docgen:tier=oss
	// docgen:auth=site_admin
	keys.DELETE("/expired", HandleDeleteExpiredKeys(deps))

	// docgen:endpoint
	// docgen:surface=keys
	// docgen:method=POST
	// docgen:path=/api/v1/keys/reload
	// docgen:summary=Reload key manager (returns 501 in OSS; KeyManager not yet relocated into OSS).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:notes=501 placeholder until KeyManager lands in OSS.
	keys.POST("/reload", HandleReloadSigningKeyNotImplemented())
}

// safeKey is the JSON projection emitted to /api/v1/keys
// responses. It deliberately omits PrivateKey — that field never
// crosses the HTTP boundary.
type safeKey struct {
	KID         string              `json:"kid"`
	Algorithm   domain.KeyAlgorithm `json:"algorithm"`
	State       domain.KeyState     `json:"state"`
	CreatedAt   time.Time           `json:"created_at"`
	ActivatedAt *time.Time          `json:"activated_at,omitempty"`
	RotatedAt   *time.Time          `json:"rotated_at,omitempty"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
	CreatedBy   *uuid.UUID          `json:"created_by,omitempty"`
	PublicKey   string              `json:"public_key"`
}

func toSafe(k domain.SigningKey) safeKey {
	return safeKey{
		KID:         k.KID,
		Algorithm:   k.Algorithm,
		State:       k.State,
		CreatedAt:   k.CreatedAt,
		ActivatedAt: k.ActivatedAt,
		RotatedAt:   k.RotatedAt,
		ExpiresAt:   k.ExpiresAt,
		CreatedBy:   k.CreatedBy,
		PublicKey:   k.PublicKey,
	}
}

// HandleListSigningKeys returns 200 + the safe-projection JWKS-like
// list of every signing key in the database. PrivateKey is never
// emitted.
//
// No audit emission: reads are not audited at the OSS layer
// (matches the monolith's behaviour).
func HandleListSigningKeys(deps KeysHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		keys, err := deps.KeyService.ListAll(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeKey, len(keys))
		for i, k := range keys {
			out[i] = toSafe(k)
		}
		c.JSON(http.StatusOK, gin.H{
			"keys":  out,
			"count": len(out),
		})
	}
}

// HandleGenerateSigningKey accepts {algorithm, state?} and creates
// a new signing key via service.KeyService.Generate.
//
// THE-PKCE-DECISION (owner ruling): RS256 generation is ALLOWED here
// — it is a real capability for conformance/interop TESTING — but it
// is NEVER the default signer: the primary key selection and
// AutoGenerateInitialKey remain EdDSA/ES256-only, and an RS256 key
// signs only id_tokens of clients that explicitly registered
// id_token_signed_response_alg=RS256. See docs/TESTING-OPERATORS.md.
//
// Successful generation emits an audit event with safe metadata
// only (KID + algorithm; no key material).
func HandleGenerateSigningKey(deps KeysHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Algorithm string `json:"algorithm"`
			State     string `json:"state"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		switch req.Algorithm {
		case string(domain.KeyAlgorithmEdDSA), string(domain.KeyAlgorithmES256), string(domain.KeyAlgorithmRS256):
			// ok — RS256 is explicit-request, testing-only (never default).
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error":     "unsupported issuance algorithm",
				"supported": []string{string(domain.KeyAlgorithmEdDSA), string(domain.KeyAlgorithmES256), string(domain.KeyAlgorithmRS256)},
			})
			return
		}

		state := domain.KeyStateRotating
		if req.State == string(domain.KeyStateActive) {
			state = domain.KeyStateActive
		}

		// CreatedBy is provenance and comes from the AUTHENTICATED
		// principal, never the wire — client-supplied provenance would
		// be spoofable (THE-TWO-DEBTS, debt A).
		var createdBy *uuid.UUID
		if actor, ok := mw.PrincipalFromContext(c); ok && actor.UserID != uuid.Nil {
			id := actor.UserID
			createdBy = &id
		}

		key, err := deps.KeyService.Generate(c.Request.Context(), service.GenerateKeyOptions{
			Algorithm: req.Algorithm,
			State:     state,
			CreatedBy: createdBy,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"kid":        key.KID,
			"algorithm":  key.Algorithm,
			"state":      key.State,
			"public_key": key.PublicKey,
		})

		// Audit (best-effort).
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "key.generated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"kid":       key.KID,
				"algorithm": string(key.Algorithm),
				"state":     string(key.State),
			},
		})
	}
}

// HandleRotateSigningKey accepts {old_kid, new_kid, deprecate_days?}
// and runs the atomic rotation via service.KeyService.Rotate.
// Successful rotation emits an audit event.
func HandleRotateSigningKey(deps KeysHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			OldKID        string `json:"old_kid"`
			NewKID        string `json:"new_kid"`
			DeprecateDays int    `json:"deprecate_days"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.OldKID == "" || req.NewKID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		var expiresAt *time.Time
		if req.DeprecateDays > 0 {
			t := time.Now().UTC().AddDate(0, 0, req.DeprecateDays)
			expiresAt = &t
		}
		if err := deps.KeyService.Rotate(c.Request.Context(), req.OldKID, req.NewKID, expiresAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"old_kid":        req.OldKID,
			"new_kid":        req.NewKID,
			"deprecate_days": req.DeprecateDays,
		})

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "key.rotated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"old_kid":        req.OldKID,
				"new_kid":        req.NewKID,
				"deprecate_days": req.DeprecateDays,
			},
		})
	}
}

// HandleDeprecateSigningKey accepts {kid, expires_at?} and marks a
// key deprecated via service.KeyService.Deprecate.
func HandleDeprecateSigningKey(deps KeysHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			KID       string    `json:"kid"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.KID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		expiresAt := req.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().UTC().AddDate(0, 0, 30)
		}
		if err := deps.KeyService.Deprecate(c.Request.Context(), req.KID, expiresAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"kid":        req.KID,
			"expires_at": expiresAt,
		})

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "key.deprecated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"kid":        req.KID,
				"expires_at": expiresAt,
			},
		})
	}
}

// HandleDeleteExpiredKeys deletes deprecated keys past their expiry
// via service.KeyService.DeleteExpired.
func HandleDeleteExpiredKeys(deps KeysHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		deleted, err := deps.KeyService.DeleteExpired(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": deleted})

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "key.expired_purged",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"deleted": deleted,
			},
		})
	}
}

// HandleReloadSigningKeyNotImplemented returns 501 because the OSS
// module does not yet ship the in-process KeyManager that the
// monolith reload endpoint refreshes. A future slice can land the
// KeyManager and replace this stub.
func HandleReloadSigningKeyNotImplemented() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":  "not implemented",
			"reason": "KeyManager not yet relocated into the OSS module; reload requires in-process key cache invalidation.",
		})
	}
}
