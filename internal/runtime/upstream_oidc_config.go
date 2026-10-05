package runtime

import (
	"fmt"
	"io"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// upstream_oidc_config.go — the default-off TEST setting that lets upstream
// OIDC sign-in reach a provider on loopback or a private network (FUNC-H4),
// so the success path can be tested end to end. Same getenv-hook convention
// as single_replica_config.go.

const upstreamPrivateIssuerEnv = "IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER"

// upstreamOIDCOptions returns the upstream OIDC transport options: the
// SSRF-guarded, https-only default, or — when the operator sets
// IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER to true — the private-issuer
// test options, announced by a startup WARNING so the setting is never silent.
// Unset, empty or malformed ⇒ the default. private reports which was chosen.
func upstreamOIDCOptions(getenv func(string) string, stderr io.Writer) (discovery service.OIDCDiscoveryOptions, callback service.OIDCCallbackServiceOptions, private bool) {
	if !resolveEnvBool(getenv, upstreamPrivateIssuerEnv) {
		return service.OIDCDiscoveryOptions{}, service.OIDCCallbackServiceOptions{}, false
	}
	fmt.Fprint(stderr, "identuum-idp: serve: WARNING "+upstreamPrivateIssuerEnv+" is set — upstream OIDC sign-in may reach "+
		"providers on loopback and private networks over plain http (the SSRF guard is off for discovery, the provider's "+
		"keys and the code exchange). This is a TEST setting; unset it in production.\n")
	discovery, callback = service.UpstreamPrivateIssuerOptions(10 * time.Second)
	return discovery, callback, true
}
