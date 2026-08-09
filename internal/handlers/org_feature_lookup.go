package handlers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OrgFeatureLookup is the narrow handler-side seam consulted by
// the DCR and SCIM foundation handlers when they need to decide
// whether a tenant has enabled the protocol they are about to
// serve.
//
// Production wiring binds this to
// `service.OrganizationProtocolSettingsService.IsFeatureEnabledForOrg`
// — that service reads `organization_protocol_settings` (or
// returns the system default when the row is absent).
//
// Test wiring can supply any implementation: a stub that
// returns true for every org keeps the existing test suites
// behaviourally unchanged; a stub keyed on orgID exercises the
// per-org enforcement contract.
//
// A nil OrgFeatureLookup in a handler dep struct is the
// documented OSS default: equivalent to "every feature is on for
// every org" (so handlers wired without the lookup retain their
// pre-correction behaviour and no existing test regresses).
type OrgFeatureLookup interface {
	// IsFeatureEnabledForOrg returns (enabled, err). On any
	// repository error the caller MUST treat the request as a
	// 500 — the org gate is fail-closed only against explicit
	// "row says false"; an internal lookup failure must NOT
	// silently allow the request.
	IsFeatureEnabledForOrg(ctx context.Context, orgID uuid.UUID, feature string) (bool, error)
}

// resolveOrgFeature is the canonical helper every DCR / SCIM
// handler call site uses. Behaviour:
//
//   - lookup == nil → returns (allowed=true, ok=true). The
//     handler treats this as the "no per-org gate wired" default
//     so an OSS deployment without OrganizationProtocolSettings
//     wiring (test fixtures, smoke binaries) keeps the
//     foundation reachable.
//   - orgID == uuid.Nil → returns (allowed=true, ok=true). The
//     request is org-less by construction (org-less DCR
//     registration of an infra-level client, SCIM discovery
//     reads that do not target a specific tenant). Document
//     each call site that supplies uuid.Nil so the policy is
//     traceable.
//   - lookup returns (enabled, nil) → returns (enabled, true).
//   - lookup returns an error → writes a 503 envelope and
//     returns (false, false). Callers MUST stop further work
//     when ok is false.
//
// The 403 disabled-feature envelope is shaped exactly like the
// existing `mw.RequireFeature` envelope so an operator monitoring
// disabled-feature 403s sees a uniform pattern.
func resolveOrgFeature(c *gin.Context, lookup OrgFeatureLookup, orgID uuid.UUID, feature string) (allowed, ok bool) {
	if lookup == nil {
		return true, true
	}
	if orgID == uuid.Nil {
		return true, true
	}
	enabled, err := lookup.IsFeatureEnabledForOrg(c.Request.Context(), orgID, feature)
	if err != nil {
		c.AbortWithStatusJSON(503, gin.H{
			"error":   "feature lookup failed",
			"feature": feature,
		})
		return false, false
	}
	return enabled, true
}

// abortOrgFeatureDisabled writes the standard 403 envelope and
// aborts the request. The envelope mirrors `mw.RequireFeature`
// so operators see a uniform shape across global + per-org gates.
func abortOrgFeatureDisabled(c *gin.Context, feature string) {
	c.AbortWithStatusJSON(403, gin.H{
		"error":   "feature not enabled",
		"feature": feature,
	})
}
