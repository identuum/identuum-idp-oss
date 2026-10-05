package runtime

import (
	"bytes"
	"strings"
	"testing"
)

// FUNC-H4: the private-issuer TEST setting is off unless explicitly set, and
// is never silent when on.
func TestUpstreamOIDCOptions_DefaultOffAndLoggedWhenOn(t *testing.T) {
	for _, v := range []string{"", "false", "0", "yes please"} {
		var stderr bytes.Buffer
		d, c, private := upstreamOIDCOptions(func(string) string { return v }, &stderr)
		if private || d.AllowPlainHTTP || d.HTTPClient != nil || c.HTTPClient != nil || stderr.Len() != 0 {
			t.Errorf("%s=%q: private=%v plain=%v, output %q; want the guarded default, silently", upstreamPrivateIssuerEnv, v, private, d.AllowPlainHTTP, stderr.String())
		}
	}
	var stderr bytes.Buffer
	d, c, private := upstreamOIDCOptions(func(k string) string {
		if k == upstreamPrivateIssuerEnv {
			return "true"
		}
		return ""
	}, &stderr)
	if !private || !d.AllowPlainHTTP || d.HTTPClient == nil || c.HTTPClient == nil {
		t.Errorf("set to true: private=%v plain=%v; want the private-issuer test options", private, d.AllowPlainHTTP)
	}
	if out := stderr.String(); !strings.Contains(out, "WARNING "+upstreamPrivateIssuerEnv) || !strings.Contains(out, "TEST setting") {
		t.Errorf("startup output = %q; want the WARNING naming the setting", out)
	}
}
