package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"html"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// frontchannelFanout collects the frames end_session renders: one per
// (relying party, ended session) that resolves to a front-channel logout URL,
// in the order they were found, each once.
type frontchannelFanout struct {
	srcs   []string
	framed map[string]struct{}
}

// add resolves rp's frame for the session sid (iss and sid appended when the
// client registered frontchannel_logout_session_required) and keeps it once.
func (f *frontchannelFanout) add(rp *domain.Client, issuer string, sid uuid.UUID) {
	if rp == nil || rp.FrontchannelLogoutURI == "" {
		return
	}
	key := rp.ClientID + "|" + sid.String()
	if _, done := f.framed[key]; done {
		return
	}
	src := resolveFrontchannelIframeSrc(rp, issuer, sid)
	if src == "" {
		return
	}
	f.framed[key] = struct{}{}
	f.srcs = append(f.srcs, src)
}

// frontchannelContinueAfter is how long the page's script waits for the
// frames before it continues anyway; the refresh the page carries for a
// browser without script (under noscript) waits a little longer. A relying
// party that never answers must not hold the person's sign-out.
const (
	frontchannelContinueAfter = "3000"
	frontchannelRefreshAfter  = "5"
)

// frontchannelFrameSandbox is the sandbox a front-channel logout frame gets
// (OSS-REVIEW-FIXES-1, review finding F1). The receiver's script must run: a
// relying party that clears its sign-in marker from storage or calls its own
// logout API is script-dependent, and a frame with no allow-scripts loaded
// it, fired load, and told the OP nothing had gone wrong. A receiver whose
// origin is positively different from the OP's also gets allow-same-origin,
// so it runs with its own origin's storage and cookies; it still cannot
// script, navigate or submit anything in the page that frames it
// (cross-origin, and no allow-top-navigation, allow-forms or allow-popups).
//
// Every other receiver gets allow-scripts alone: one on the OP's own origin
// under any spelling a browser treats as that origin (a zero-padded default
// port, an IPv6 literal written long or short; FRONTCHANNEL-SANDBOX-ORIGIN-1,
// review OSS-FIXES-REVIEW-2026-10-10 R1), and one whose origin, or the OP's,
// cannot be canonicalized with certainty — which includes every
// internationalized (Unicode or punycode) host, so an IDNA alias of the OP
// is never granted both either. allow-scripts with allow-same-origin on a same-origin document
// would let it read the page that frames it and lift its own sandbox, so
// that pair is never granted to it. The price (R2): such a receiver's script
// runs in an opaque origin, without its origin's storage or cookies. A
// receiver that must clear browser storage is served from an origin other
// than the issuer's; back-channel logout is the alternative.
func frontchannelFrameSandbox(src, issuer string) string {
	rp, op := webOrigin(src), webOrigin(issuer)
	if rp != "" && op != "" && rp != op {
		return "allow-scripts allow-same-origin"
	}
	return "allow-scripts"
}

// webOrigin is raw's origin as a browser computes it, so that two spellings
// of one origin compare equal: the scheme (http or https), the host in
// lower-case ASCII (an IP literal in its canonical form, one trailing dot
// dropped), and the port as a number with the scheme's default dropped. It
// answers "" for anything it cannot canonicalize with certainty — another
// scheme, userinfo, an internationalized host, a host a browser would read as
// an IPv4 address written other than as four decimal parts, a port out of
// range — and the caller then treats the origin as possibly the OP's own.
func webOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" {
		return ""
	}
	defaultPort := map[string]int{"http": 80, "https": 443}[u.Scheme]
	if defaultPort == 0 {
		return ""
	}
	host := canonicalOriginHost(u.Host, u.Hostname())
	if host == "" {
		return ""
	}
	origin := u.Scheme + "://" + host
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return ""
		}
		if n != defaultPort {
			origin += ":" + strconv.Itoa(n)
		}
	}
	return origin
}

// canonicalOriginHost is the host part of webOrigin; rawHost is the URL's
// host with its port, hostname the same without port or IPv6 brackets.
func canonicalOriginHost(rawHost, hostname string) string {
	if strings.HasPrefix(rawHost, "[") {
		addr, err := netip.ParseAddr(hostname)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return ""
		}
		return "[" + addr.String() + "]"
	}
	ascii := strings.ToLower(strings.TrimSuffix(hostname, "."))
	if ascii == "" {
		return ""
	}
	// An internationalized host — non-ASCII, or a punycode (xn--) label —
	// has several spellings a browser maps to one origin through IDNA. This
	// package may not import an IDNA mapper (boundaries.json), so such a host
	// is not canonicalized at all: it is never judged different from the OP.
	for i := 0; i < len(ascii); i++ {
		if ascii[i] >= 0x80 {
			return ""
		}
	}
	labels := strings.Split(ascii, ".")
	for _, l := range labels {
		if strings.HasPrefix(l, "xn--") {
			return ""
		}
	}
	if last := labels[len(labels)-1]; isNumericHostLabel(last) {
		// A browser reads this host as an IPv4 address, in any of several
		// notations; only the plain dotted-decimal one is trusted here.
		addr, err := netip.ParseAddr(ascii)
		if err != nil || !addr.Is4() || addr.String() != ascii {
			return ""
		}
	}
	return ascii
}

// isNumericHostLabel reports whether a host's last label makes a browser
// parse the host as IPv4: decimal digits, or 0x followed by hex digits.
func isNumericHostLabel(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

// renderFrontchannelFanoutPage writes the page that loads each front-channel
// logout frame and then continues to continueTo; with continueTo empty it is
// the signed-out page carrying the frames. The policy admits exactly the
// frames' origins and, when there is somewhere to continue to, one script by
// nonce; nothing else loads, nothing is cached, and no token is in any URL.
// issuer is the OP's own address, which decides each frame's sandbox.
func renderFrontchannelFanoutPage(c *gin.Context, srcs []string, continueTo, issuer string) {
	origins := make([]string, 0, len(srcs))
	seen := map[string]struct{}{}
	for _, src := range srcs {
		o := iframeOrigin(src)
		if _, done := seen[o]; o == "" || done {
			continue
		}
		seen[o] = struct{}{}
		origins = append(origins, o)
	}
	scriptSrc := "'none'"
	nonce := ""
	if continueTo != "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err == nil {
			nonce = base64.StdEncoding.EncodeToString(raw)
			scriptSrc = "'nonce-" + nonce + "'"
		}
	}
	csp := "default-src 'none'; script-src " + scriptSrc + "; style-src 'unsafe-inline'; img-src 'none'"
	if len(origins) > 0 {
		csp += "; frame-src " + strings.Join(origins, " ")
	}
	csp += "; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	if continueTo != "" {
		// Exactly one navigation: the script below continues; a browser
		// without script continues by this refresh, which lives under
		// noscript so a scripted browser never also fires it (the
		// conformance suite's browser followed both, and the second
		// post_logout_redirect arrival failed its module).
		b.WriteString("  <noscript><meta http-equiv=\"refresh\" content=\"" + frontchannelRefreshAfter + ";url=" + html.EscapeString(continueTo) + "\"></noscript>\n")
		b.WriteString("  <title>Signing out — Identuum</title>\n")
	} else {
		b.WriteString("  <title>Signed out — Identuum</title>\n")
	}
	b.WriteString("  <style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1c1917}h1{font-size:1.5rem}iframe{border:0;width:1px;height:1px;position:absolute;left:-9999px;visibility:hidden}</style>\n</head>\n<body>\n  <main>\n")
	if continueTo != "" {
		b.WriteString("    <h1>Signing you out</h1>\n    <p>Your session with the identity provider has ended. The applications you signed in to are being told; you will be returned to the application in a moment.</p>\n")
		b.WriteString("    <p><a id=\"continue\" href=\"" + html.EscapeString(continueTo) + "\">Continue</a></p>\n")
	} else {
		b.WriteString("    <h1>You are signed out</h1>\n    <p>Your session with the identity provider has ended. The applications you signed in to are being told. You can close this window.</p>\n")
	}
	b.WriteString("  </main>\n")
	for _, src := range srcs {
		b.WriteString("  <iframe src=\"" + html.EscapeString(src) + "\" sandbox=\"" + frontchannelFrameSandbox(src, issuer) + "\" title=\"Signing out of an application\"></iframe>\n")
	}
	if nonce != "" {
		// Continue once every frame has loaded or failed, and never later
		// than frontchannelContinueAfter; the link's href is the one target.
		b.WriteString("  <script nonce=\"" + nonce + "\">(function(){var a=document.getElementById('continue');if(!a){return;}var frames=document.getElementsByTagName('iframe');var left=frames.length;var done=false;function go(){if(done){return;}done=true;window.location.replace(a.href);}function one(){left--;if(left<=0){go();}}for(var i=0;i<frames.length;i++){frames[i].addEventListener('load',one);frames[i].addEventListener('error',one);}if(left<=0){go();}setTimeout(go," + frontchannelContinueAfter + ");})();</script>\n")
	}
	b.WriteString("</body>\n</html>")

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Security-Policy", csp)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.String(http.StatusOK, b.String())
}
