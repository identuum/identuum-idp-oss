package mw

// Phase 1 open-core test (slice
// identuum-idp-open-core-phase1-feature-gate-interface): exercise
// mw.RequireFeature against the core-owned
// features.StarterFeatureGate so the test surface is independent of
// internal/license. This proves that any future
// FeatureGate-conformant gate (including the Starter stub a hypothetical
// identuum-idp-oss build would use) works as a drop-in.
//
// The existing TestRequireFeature_* tier tests continue to pass
// *license.Service through to the same middleware and cover the
// production path.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/identuum/identuum-idp-oss/internal/features"
)

func TestRequireFeature_StarterGate_AllowsStarterFeature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gate := features.StarterFeatureGate{}

	router := gin.New()
	router.Use(RequireFeature(gate, features.WebAuthn))
	router.GET("/ok", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"ok":true`)
}

func TestRequireFeature_StarterGate_DeniesCommercialFeature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gate := features.StarterFeatureGate{}

	router := gin.New()
	router.Use(RequireFeature(gate, features.SCIM))
	router.GET("/scim/v2/Users", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"Starter gate must deny commercial feature with the existing 403 wire shape")
	assert.Contains(t, w.Body.String(), "not available on your current license tier",
		"Response body must match the existing wire format byte-for-byte")
}

// fakeGate is a minimal FeatureGate test double that returns a
// pre-configured answer. It proves RequireFeature now depends only
// on the interface — no internal/license types are needed in this
// file.
type fakeGate struct {
	allow bool
}

func (f fakeGate) IsFeatureEnabled(feature string, roles ...string) bool {
	return f.allow
}

func TestRequireFeature_AcceptsAnyFeatureGate_Allow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireFeature(fakeGate{allow: true}, "any_feature"))
	router.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireFeature_AcceptsAnyFeatureGate_Deny(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireFeature(fakeGate{allow: false}, "any_feature"))
	router.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "not available on your current license tier")
}
