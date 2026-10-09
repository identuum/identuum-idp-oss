package runtime

import (
	"fmt"
	"io"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// backchannel_receiver_config.go — the default-off TEST setting that lets a
// back-channel logout delivery reach a receiver on loopback or a private
// network (OSS-BACKCHANNEL-TEST-SEAM), so the delivered path can be tested end
// to end against a local receiver. The mirror of upstream_oidc_config.go:
// same getenv hook, same default, same WARNING at boot.

const backchannelPrivateReceiverEnv = "IDENTUUM_IDP_TEST_ALLOW_PRIVATE_BACKCHANNEL_RECEIVER"

// backchannelReceiverOptions returns the back-channel delivery options: the
// SSRF-guarded, https-only default, or — when the operator sets
// IDENTUUM_IDP_TEST_ALLOW_PRIVATE_BACKCHANNEL_RECEIVER to true — the
// private-receiver test options, announced by a startup WARNING so the
// setting is never silent. Unset, empty or malformed ⇒ the default. private
// reports which was chosen; the caller relaxes registration on the same answer.
func backchannelReceiverOptions(getenv func(string) string, stderr io.Writer) (opts service.BackchannelLogoutServiceOptions, private bool) {
	if !resolveEnvBool(getenv, backchannelPrivateReceiverEnv) {
		return service.BackchannelLogoutServiceOptions{}, false
	}
	fmt.Fprint(stderr, "identuum-idp: serve: WARNING "+backchannelPrivateReceiverEnv+" is set — back-channel logout deliveries may reach "+
		"receivers on loopback and private networks over plain http (the SSRF guard and the https rule are off for "+
		"backchannel_logout_uri, at registration and at delivery). This is a TEST setting; unset it in production.\n")
	return service.BackchannelPrivateReceiverOptions(3 * time.Second), true
}
