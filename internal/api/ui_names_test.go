package api

import "github.com/identuum/identuum-idp-oss/pkg/uiserve"

// The UI proofs in this package drive the whole OSS engine; the boundary's
// constants now live in pkg/uiserve (PLAN-F-1). These names keep the proofs
// unchanged.
const (
	uiBFFRequiredHeader      = uiserve.RequestHeader
	uiBFFRequiredHeaderValue = uiserve.RequestHeaderValue
	uiBFFLogoutPath          = uiserve.LogoutPath
	uiShellCacheControl      = uiserve.ShellCacheControl
	uiAssetCacheControl      = uiserve.AssetCacheControl
	uiGinNotFoundBody        = uiserve.NotFoundBody
)
