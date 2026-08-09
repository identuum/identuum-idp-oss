package mw

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/pkg/features"
	"github.com/identuum/identuum-idp-oss/types"
)

// RequireFeature returns a Gin middleware that aborts with 403 if
// the requested feature is not enabled according to the supplied
// features.FeatureGate. Use this as the first middleware on any
// premium route group.
//
// Phase 1 of the open-core split
// (identuum-idp-open-core-phase1-feature-gate-interface):
// RequireFeature previously accepted a concrete *license.Service.
// It now accepts the core-owned features.FeatureGate interface so
// that mw no longer imports internal/license in production source.
// Existing production wiring still passes *license.Service (which
// satisfies the interface structurally — see
// internal/license/gate_compat.go), so runtime behaviour is
// unchanged.
func RequireFeature(gate features.FeatureGate, feature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !gate.IsFeatureEnabled(feature) {
			// Middleware cannot import internal/handlers (circular import via handler_mfa_stepup.go).
			// Emit the identical types.ErrorResponse wire format that RespondWithError+MapError would produce.
			c.JSON(http.StatusForbidden, types.ErrorResponse{
				Success: false,
				Message: "This feature is not available on your current license tier",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
