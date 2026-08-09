package mw

// Phase T1 open-core test: exercise mw.RequireFeature against the
// new public pkg/features seam. This proves the CE overlay path —
// importing only github.com/identuum/identuum-idp-oss/pkg/features
// — can wire the existing mw.RequireFeature middleware without
// crossing the internal/ boundary.
//
// The existing TestRequireFeature_StarterGate_* tests in
// require_feature_starter_gate_test.go continue to exercise the
// same middleware via the internal/features import path, proving
// the alias is bidirectional and the underlying behavior is
// unchanged.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	pkgfeatures "github.com/identuum/identuum-idp-oss/pkg/features"
	pkglp "github.com/identuum/identuum-idp-oss/pkg/licenseprovider"
)

func TestRequireFeature_PublicSeam_AllowsStarterFeature(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireFeature(pkgfeatures.StarterFeatureGate{}, pkgfeatures.WebAuthn))
	router.GET("/ok", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"ok":true`)
}

func TestRequireFeature_PublicSeam_DeniesCommercialFeature(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireFeature(pkgfeatures.StarterFeatureGate{}, pkgfeatures.SCIM))
	router.GET("/scim/v2/Users", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"Starter gate from public seam must deny commercial feature")
	assert.Contains(t, w.Body.String(), "not available on your current license tier",
		"Wire format must be preserved through the public seam")
}

// TestRequireFeature_AcceptsPublicProvider verifies that a value
// of pkg/licenseprovider.Provider (the same shape CE will hand in)
// satisfies the FeatureGate parameter of RequireFeature. This is
// the smallest concrete proof that the CE composition path works.
func TestRequireFeature_AcceptsPublicProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	provider := pkglp.NewStarterProvider() // implements pkgfeatures.FeatureGate

	allowRouter := gin.New()
	allowRouter.Use(RequireFeature(provider, pkgfeatures.Core))
	allowRouter.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	allowW := httptest.NewRecorder()
	allowRouter.ServeHTTP(allowW, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, allowW.Code)

	denyRouter := gin.New()
	denyRouter.Use(RequireFeature(provider, pkgfeatures.SCIM))
	denyRouter.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	denyW := httptest.NewRecorder()
	denyRouter.ServeHTTP(denyW, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusForbidden, denyW.Code)
}
