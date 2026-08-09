package service

// clock_seam_boundary_authorize_test.go — the session-expiry instant the
// authorize endpoint decides on (THE-FLOOR-IS-NOT-THE-TOTAL, 2026-08-04).
//
// WHY THIS SEAM ONLY SHOWS UP NOW. AuthorizeService.now reads once:
//
//	if canUse, _ := session.CanBeUsed(s.now().UTC()); !canUse {
//
// and the comparison is three calls away — CanBeUsed -> IsExpired -> After —
// in ANOTHER PACKAGE (internal/domain). Every classifier this fleet has had
// stopped short of it, so the seam sat on the never-injected list reading
// STAMP: a live authentication deadline that no test could stand on.
//
// THE OPERATOR IS `now.After(s.ExpiresAt)`, so a session is still usable AT the
// instant it expires — PERMISSIVE, the opposite of par's `!now.Before(exp)`
// deadlines one repo over, and the reason each one is read before it is asserted.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// seamAuthorizeEpoch is far from any plausible wall clock: with the injection
// removed the comparison runs against today and the assertion fails loudly
// rather than drifting into a date-dependent pass.
var seamAuthorizeEpoch = time.Date(2031, 3, 1, 12, 0, 0, 0, time.UTC)

// TestAuthorizeSeam_SessionUsableExactlyAtExpiry pins AuthorizeService.now.
func TestAuthorizeSeam_SessionUsableExactlyAtExpiry(t *testing.T) {
	verifier, challenge := authorizeChallenge(t)
	_ = verifier

	// THE SERVICE IS BUILT HERE RATHER THAN THROUGH newAuthorizeHarness, and that
	// is load-bearing for the census, not a style choice. The harness returns
	// THREE values, and clockfuse resolves an assignment's receiver through
	// SINGLE-result constructors — so `svc, _, sess := newAuthorizeHarness(t)`
	// followed by `svc.now = ...` is an unattributable write, which credits
	// nothing and shadows every other `now` in the package into UNDECIDED.
	newCase := func(t *testing.T, clock time.Time) (*AuthorizeService, AuthorizeRequest) {
		t.Helper()
		sid := uuid.New()
		clients := &fakeAuthorizeClientLookup{
			client: &domain.Client{
				ClientID:     "cli-1",
				Name:         "Test client",
				RedirectURIs: []string{"https://app.example.com/cb"},
				SkipConsent:  true,
			},
		}
		codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
		// The deadline is a LITERAL, never derived from the injected clock: a test
		// whose every instant comes from the clock passes under ANY consistent
		// clock, including the wall clock, and proves nothing about the seam.
		sess := &fakeAuthorizeSessionLookup{
			session: &domain.Session{
				ID:        sid,
				UserID:    uuid.New(),
				IsValid:   true,
				CreatedAt: seamAuthorizeEpoch.Add(-time.Hour),
				ExpiresAt: seamAuthorizeEpoch,
			},
		}
		svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
			WithSessionLookup(sess)
		svc.now = func() time.Time { return clock }
		return svc, newAuthorizeRequest(challenge, authorizePrincipal(sid))
	}

	// EXACTLY at ExpiresAt the session is still usable: `now.After(exp)` is false
	// when now == exp.
	svc, req := newCase(t, seamAuthorizeEpoch)
	if _, err := svc.Authorize(context.Background(), req); err != nil {
		t.Fatalf("at ExpiresAt exactly: err = %v, want nil — now.After(exp) is PERMISSIVE", err)
	}

	// One nanosecond later the same session is refused.
	svc2, req2 := newCase(t, seamAuthorizeEpoch.Add(time.Nanosecond))
	if _, err := svc2.Authorize(context.Background(), req2); err == nil {
		t.Error("a nanosecond past ExpiresAt the session must be refused")
	}
}
