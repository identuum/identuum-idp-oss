package service

// acr_context.go — THE-HONEST-ACR: the service layer is the only layer
// below the handlers that may import the top-level `auth` package
// (boundaries.json). Handlers and the router reach the acr vocabulary
// through these re-exports instead of importing `auth` directly, so the
// architecture boundary stays exactly as strict as it was.

import "github.com/identuum/identuum-idp-oss/auth"

// The acr ladder rungs a local login can stamp (see auth/acr.go).
const (
	ACRPassword          = auth.ACRPassword
	ACRMFA               = auth.ACRMFA
	ACRPhishingResistant = auth.ACRPhishingResistant
)

// The amr values this OP stamps (RFC 8176; see auth/acr_login.go).
const (
	AMRPassword = auth.AMRPassword
	AMROTP      = auth.AMROTP
)

// AdvertisedACRValues is discovery's acr_values_supported — exactly the
// contexts a local login performs or steps up to.
func AdvertisedACRValues() []string { return auth.AdvertisedACRValues() }

// LoginContext returns the (acr, amr) a local login performed.
func LoginContext(mfaVerified bool) (acr string, amr []string) {
	return auth.LoginContext(mfaVerified)
}
