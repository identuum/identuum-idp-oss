package service

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newCSRFHarness(t *testing.T) *BrowserCSRFService {
	t.Helper()
	return NewBrowserCSRFService(nil, BrowserCSRFServiceOptions{
		Secret: []byte("00112233445566778899aabbccddeeff00112233"),
		TTL:    5 * time.Minute,
	})
}

// ---------- Construction ----------

func TestNewBrowserCSRFService_TooShortSecretPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("short secret did not panic")
		}
	}()
	_ = NewBrowserCSRFService(nil, BrowserCSRFServiceOptions{Secret: []byte("too-short")})
}

func TestNewBrowserCSRFService_TTLClampedToHour(t *testing.T) {
	svc := NewBrowserCSRFService(nil, BrowserCSRFServiceOptions{
		Secret: []byte("00112233445566778899aabbccddeeff00112233"),
		TTL:    24 * time.Hour,
	})
	if svc.ttl != time.Hour {
		t.Errorf("ttl = %v, want clamped to 1h", svc.ttl)
	}
}

// ---------- Issue + Verify ----------

func TestCSRF_IssueProducesParseableToken(t *testing.T) {
	svc := newCSRFHarness(t)
	tok, cookie, err := svc.Issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cookie.Name != "identuum_csrf" {
		t.Errorf("cookie name = %q", cookie.Name)
	}
	// The service leaves Secure=false: it cannot see the request, so it
	// cannot know the transport. The HTTP handler stamps the transport-correct
	// Secure flag via writeBrowserCSRFCookie/cookieSecureForRequest (true in
	// production, false over http://localhost) — pinned by the handler-layer
	// TestBrowserLoginCSRFCookie_SecureFollowsTransport (BROWSER-LOGIN-PLAINHTTP-1).
	if cookie.Secure {
		t.Errorf("service-layer cookie must leave Secure=false (handler stamps transport)")
	}
	if cookie.HttpOnly {
		t.Errorf("cookie MUST NOT be HttpOnly (form needs to read it)")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v", cookie.SameSite)
	}
	if strings.Count(tok, ".") != 2 {
		t.Errorf("token shape wrong: %q", tok)
	}
}

func TestCSRF_VerifyHappyPath(t *testing.T) {
	svc := newCSRFHarness(t)
	tok, cookie, _ := svc.Issue()
	if err := svc.Verify(cookie.Value, tok); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestCSRF_VerifyMissingTokenRejected(t *testing.T) {
	svc := newCSRFHarness(t)
	if err := svc.Verify("", "x"); !errors.Is(err, ErrBrowserCSRFMissing) {
		t.Errorf("err = %v", err)
	}
	if err := svc.Verify("x", ""); !errors.Is(err, ErrBrowserCSRFMissing) {
		t.Errorf("err = %v", err)
	}
}

func TestCSRF_VerifyMismatchRejected(t *testing.T) {
	svc := newCSRFHarness(t)
	tok, cookie, _ := svc.Issue()
	if err := svc.Verify(cookie.Value, tok+"x"); !errors.Is(err, ErrBrowserCSRFInvalid) {
		t.Errorf("err = %v", err)
	}
}

// RULE: CSRF-VERIFY-1
func TestCSRF_VerifyForgedTagRejected(t *testing.T) {
	svc := newCSRFHarness(t)
	// Hand-craft a token whose tag will not verify under the
	// service's HMAC key.
	forged := "deadbeef.9999999999.0000000000000000000000000000000000000000000000000000000000000000"
	if err := svc.Verify(forged, forged); !errors.Is(err, ErrBrowserCSRFInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestCSRF_VerifyExpiredRejected(t *testing.T) {
	svc := newCSRFHarness(t)
	frozen := time.Now()
	svc.now = func() time.Time { return frozen }
	tok, cookie, _ := svc.Issue()
	// Jump past expiry.
	svc.now = func() time.Time { return frozen.Add(10 * time.Minute) }
	if err := svc.Verify(cookie.Value, tok); !errors.Is(err, ErrBrowserCSRFExpired) {
		t.Errorf("err = %v", err)
	}
}

func TestCSRF_VerifyMalformedRejected(t *testing.T) {
	svc := newCSRFHarness(t)
	if err := svc.Verify("garbage", "garbage"); !errors.Is(err, ErrBrowserCSRFMalformed) {
		t.Errorf("err = %v", err)
	}
}

// ---------- Clear ----------

func TestCSRF_ClearMatchesIssueFlags(t *testing.T) {
	svc := newCSRFHarness(t)
	c := svc.Clear()
	if c.Value != "" {
		t.Errorf("clear value = %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("clear MaxAge = %d", c.MaxAge)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("clear SameSite = %v", c.SameSite)
	}
}

// ---------- Names ----------

func TestCSRF_CanonicalNames(t *testing.T) {
	svc := newCSRFHarness(t)
	if svc.CookieName() != "identuum_csrf" {
		t.Errorf("cookie name drift: %q", svc.CookieName())
	}
	if svc.FormFieldName() != "csrf_token" {
		t.Errorf("form field name drift: %q", svc.FormFieldName())
	}
}
