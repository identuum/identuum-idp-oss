// Package service — BrowserCSRFService implements the double-
// submit CSRF model for the OSS browser surfaces (browser login,
// consent). The service is stateless: it does NOT persist tokens.
// Each token is an HMAC-SHA-256 over `<purpose>|<random>|<exp>`,
// keyed by an operator-supplied 32-byte secret. The wire shape is
//
//	<random-hex>.<exp-unix>.<hmac-hex>
//
// Verification splits the token, recomputes the HMAC over the
// same canonical message, constant-time compares against the
// supplied tag, and checks that `now < exp`.
//
// The token is delivered in TWO places per RFC 7231 §9.5
// "double-submit cookie" guidance:
//
//   - a non-HttpOnly cookie (`identuum_csrf`) the browser
//     auto-submits with the form, AND
//   - a hidden form input (`csrf_token`) the GET handler renders.
//
// At POST time the handler reads BOTH and rejects unless they
// match each other AND verify under the HMAC key. The cookie is
// non-HttpOnly intentionally — the form needs to read it to echo
// it back. SameSite=Lax + Secure (in non-AllowPlainHTTP mode) +
// short TTL bound the blast radius.
//
// What the service does NOT do:
//
//   - It does not bind the token to a specific user — anyone with
//     the matching cookie + hidden field can submit. Use the
//     existing session-cookie path for user-binding; CSRF is the
//     cross-origin defence layer above it.
//   - It does not persist used tokens. A leaked token is reusable
//     until it expires (default 15 min). Operators that need
//     strict one-time semantics can build a Redis blacklist on
//     top.
package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// Canonical CSRF cookie name. Kept package-level so handlers and
// tests share one source of truth.
const browserCSRFCookieName = "identuum_csrf"

// BrowserCSRFService issues + verifies double-submit CSRF tokens.
type BrowserCSRFService struct {
	secret         []byte
	ttl            time.Duration
	allowPlainHTTP bool
	now            func() time.Time
}

// BrowserCSRFServiceOptions parameterises the service.
//
//   - Secret is REQUIRED. MUST be >= 32 bytes (256 bits of entropy).
//     Misconfigured callers panic at construction.
//   - TTL defaults to 15 minutes; capped at 1 hour to bound a
//     stolen-cookie's window.
//   - AllowPlainHTTP turns OFF the Secure flag (for local dev
//     only).
type BrowserCSRFServiceOptions struct {
	Secret         []byte
	TTL            time.Duration
	AllowPlainHTTP bool
}

// NewBrowserCSRFService constructs the service. Secret <32 bytes
// or TTL <= 0 with no default fallback panic.
func NewBrowserCSRFService(report *lifecycle.StartupReport, opts BrowserCSRFServiceOptions) *BrowserCSRFService {
	if len(opts.Secret) < 32 {
		report.Fatal("NewBrowserCSRFService", "service: NewBrowserCSRFService requires a >=32-byte Secret")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	return &BrowserCSRFService{
		secret:         append([]byte(nil), opts.Secret...),
		ttl:            ttl,
		allowPlainHTTP: opts.AllowPlainHTTP,
		now:            time.Now,
	}
}

// Sentinel errors. Wire-side handlers map ALL of these to
// `403 Forbidden` so the response shape cannot distinguish
// missing/expired/mismatched/forged tokens.
var (
	ErrBrowserCSRFMissing   = errors.New("service: csrf token missing")
	ErrBrowserCSRFMalformed = errors.New("service: csrf token malformed")
	ErrBrowserCSRFExpired   = errors.New("service: csrf token expired")
	ErrBrowserCSRFInvalid   = errors.New("service: csrf token invalid")
)

// Issue mints a fresh CSRF token. Returns the token string the
// GET handler renders into the hidden form input AND the cookie
// the handler plants on the response.
func (s *BrowserCSRFService) Issue() (string, *http.Cookie, error) {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		return "", nil, err
	}
	exp := s.now().Add(s.ttl).Unix()
	rndHex := hex.EncodeToString(rnd)
	expStr := strconv.FormatInt(exp, 10)
	tag := s.sign(rndHex + "|" + expStr)
	token := rndHex + "." + expStr + "." + tag
	cookie := &http.Cookie{
		Name:    browserCSRFCookieName,
		Value:   token,
		Path:    "/",
		Expires: time.Unix(exp, 0),
		MaxAge:  int(time.Until(time.Unix(exp, 0)).Seconds()),
		// HttpOnly=false on purpose: the form template needs to
		// be able to echo the token into a hidden input. The
		// double-submit shape compensates — both cookie AND
		// hidden field must match each other AND verify under
		// the HMAC key.
		HttpOnly: false,
		Secure:   !s.allowPlainHTTP,
		SameSite: http.SameSiteLaxMode,
	}
	return token, cookie, nil
}

// Verify checks that:
//
//   - the cookie value AND the hidden form input are non-empty,
//   - they match byte-for-byte,
//   - the token parses (`rnd.exp.tag` shape),
//   - the HMAC tag verifies under the service secret,
//   - the embedded exp is still in the future.
//
// A success returns nil. A failure returns one of the granular
// sentinels above; the handler maps them to 403.
func (s *BrowserCSRFService) Verify(cookieValue, formValue string) error {
	if cookieValue == "" || formValue == "" {
		return ErrBrowserCSRFMissing
	}
	if subtle.ConstantTimeCompare([]byte(cookieValue), []byte(formValue)) != 1 {
		return ErrBrowserCSRFInvalid
	}
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 3 {
		return ErrBrowserCSRFMalformed
	}
	rndHex, expStr, tag := parts[0], parts[1], parts[2]
	if rndHex == "" || expStr == "" || tag == "" {
		return ErrBrowserCSRFMalformed
	}
	want := s.sign(rndHex + "|" + expStr)
	if subtle.ConstantTimeCompare([]byte(want), []byte(tag)) != 1 {
		return ErrBrowserCSRFInvalid
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrBrowserCSRFMalformed
	}
	if s.now().Unix() >= exp {
		return ErrBrowserCSRFExpired
	}
	return nil
}

// Clear returns the cookie the logout handler plants to revoke a
// live CSRF token.
func (s *BrowserCSRFService) Clear() *http.Cookie {
	return &http.Cookie{
		Name:     browserCSRFCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   !s.allowPlainHTTP,
		SameSite: http.SameSiteLaxMode,
	}
}

// CookieName returns the canonical CSRF cookie name (so handlers
// + tests do not duplicate the constant).
func (s *BrowserCSRFService) CookieName() string { return browserCSRFCookieName }

// FormFieldName returns the canonical hidden-form-input name.
func (s *BrowserCSRFService) FormFieldName() string { return "csrf_token" }

// sign returns the hex-encoded HMAC-SHA-256 of msg under the
// service secret.
func (s *BrowserCSRFService) sign(msg string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
