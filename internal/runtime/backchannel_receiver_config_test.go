package runtime

import (
	"bytes"
	"strings"
	"testing"
)

// OSS-BACKCHANNEL-TEST-SEAM: the private-receiver TEST setting is off unless
// explicitly set, and is never silent when on. Mirrors the upstream-issuer
// setting's test.
func TestBackchannelReceiverOptions_DefaultOffAndLoggedWhenOn(t *testing.T) {
	for _, v := range []string{"", "false", "0", "yes please"} {
		var stderr bytes.Buffer
		o, private := backchannelReceiverOptions(func(string) string { return v }, &stderr)
		if private || o.AllowPlainHTTP || o.HTTPClient != nil || o.Timeout != 0 || stderr.Len() != 0 {
			t.Errorf("%s=%q: private=%v plain=%v, output %q; want the guarded default, silently", backchannelPrivateReceiverEnv, v, private, o.AllowPlainHTTP, stderr.String())
		}
	}
	var stderr bytes.Buffer
	o, private := backchannelReceiverOptions(func(k string) string {
		if k == backchannelPrivateReceiverEnv {
			return "true"
		}
		return ""
	}, &stderr)
	if !private || !o.AllowPlainHTTP || o.HTTPClient == nil {
		t.Errorf("set to true: private=%v plain=%v; want the private-receiver test options", private, o.AllowPlainHTTP)
	}
	if out := stderr.String(); !strings.Contains(out, "WARNING "+backchannelPrivateReceiverEnv) || !strings.Contains(out, "TEST setting") {
		t.Errorf("startup output = %q; want the WARNING naming the setting", out)
	}
}
