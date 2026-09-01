package service

// THE-SECOND-LOGIN — forced re-authentication at the authorize endpoint
// (OIDC Core §3.1.2.1): prompt=login and an exceeded max_age send an
// ALREADY-authenticated principal back through the login ceremony; a
// max_age still within its window proceeds; a malformed max_age is a
// redirect-safe invalid_request; prompt=none keeps the login_required
// sentinel (the handler maps it to the OIDC-required error redirect).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// reauthHarness: a pre-approved client (SkipConsent) with a LIVE session
// whose auth_time (CreatedAt) is `age` old — the ceremony would mint a code
// were it not for the re-auth gates under test.
func reauthHarness(t *testing.T, age time.Duration) (*AuthorizeService, *domain.Principal) {
	t.Helper()
	svc, _, sess := newAuthorizeHarness(t, true)
	sess.session.CreatedAt = time.Now().Add(-age)
	return svc, authorizePrincipal(sess.session.ID)
}

// prompt=login MUST re-authenticate even with a live session and a
// pre-approved client — the ceremony is forced, no code mints.
// RULE: AUTHZ-REAUTH-1
func TestAuthorize_PromptLoginForcesCeremony(t *testing.T) {
	svc, principal := reauthHarness(t, time.Minute)
	_, challenge := authorizeChallenge(t)

	// Baseline: the same request WITHOUT prompt=login mints a code, so the
	// refusal below is attributable to the prompt alone.
	base := newAuthorizeRequest(challenge, principal)
	if _, err := svc.Authorize(context.Background(), base); err != nil {
		t.Fatalf("baseline authorize: %v", err)
	}

	for _, prompt := range []string{"login", "login consent", "LOGIN"} {
		req := newAuthorizeRequest(challenge, principal)
		req.Prompt = prompt
		if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeLoginRequired) {
			t.Errorf("prompt=%q err = %v, want ErrAuthorizeLoginRequired — the ceremony must be forced", prompt, err)
		}
	}
}

// max_age: an auth_time older than max_age seconds forces the ceremony; one
// within the window proceeds and mints a code.
func TestAuthorize_MaxAgeExceededForcesCeremony(t *testing.T) {
	svc, principal := reauthHarness(t, 10*time.Minute)
	_, challenge := authorizeChallenge(t)

	stale := newAuthorizeRequest(challenge, principal)
	stale.MaxAge = "60"
	if _, err := svc.Authorize(context.Background(), stale); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Errorf("max_age=60 on a 10-minute-old session: err = %v, want ErrAuthorizeLoginRequired", err)
	}

	fresh := newAuthorizeRequest(challenge, principal)
	fresh.MaxAge = "3600"
	if _, err := svc.Authorize(context.Background(), fresh); err != nil {
		t.Errorf("max_age=3600 on a 10-minute-old session: err = %v, want a code", err)
	}
}

// max_age=0 demands authentication NOW — any measurable age forces.
func TestAuthorize_MaxAgeZeroForcesCeremony(t *testing.T) {
	svc, principal := reauthHarness(t, 2*time.Second)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.MaxAge = "0"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Errorf("max_age=0 err = %v, want ErrAuthorizeLoginRequired", err)
	}
}

// A malformed max_age is refused redirect-safe as invalid_request — before
// authentication, so an anonymous caller gets the same answer.
func TestAuthorize_InvalidMaxAgeIsInvalidRequest(t *testing.T) {
	svc, principal := reauthHarness(t, time.Minute)
	_, challenge := authorizeChallenge(t)
	for _, bad := range []string{"abc", "-1", "1.5"} {
		req := newAuthorizeRequest(challenge, principal)
		req.MaxAge = bad
		if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeInvalidMaxAge) {
			t.Errorf("max_age=%q err = %v, want ErrAuthorizeInvalidMaxAge", bad, err)
		}
	}
	anon := newAuthorizeRequest(challenge, nil)
	anon.MaxAge = "abc"
	if _, err := svc.Authorize(context.Background(), anon); !errors.Is(err, ErrAuthorizeInvalidMaxAge) {
		t.Errorf("anonymous max_age=abc err = %v, want ErrAuthorizeInvalidMaxAge (refused before authentication)", err)
	}
}

// prompt=none + a stale max_age: the sentinel stays login_required — the
// handler turns it into the OIDC-required error redirect, never a form.
func TestAuthorize_PromptNoneStaleMaxAgeIsLoginRequired(t *testing.T) {
	svc, principal := reauthHarness(t, 10*time.Minute)
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.Prompt = "none"
	req.MaxAge = "60"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Errorf("prompt=none + stale max_age: err = %v, want ErrAuthorizeLoginRequired", err)
	}
}

// auth_time is MONOTONIC across forced ceremonies: a fresh login mints a NEW
// session, and EffectiveAuthTime (creation, or the last ACR uplift) of the
// later session is later than the first's — the first session is untouched.
func TestSession_EffectiveAuthTimeAdvancesWithAFreshSession(t *testing.T) {
	first := &domain.Session{ID: uuid.New(), UserID: uuid.New(), CreatedAt: time.Now().Add(-10 * time.Minute), ExpiresAt: time.Now().Add(time.Hour), IsValid: true}
	second := &domain.Session{ID: uuid.New(), UserID: first.UserID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), IsValid: true}
	if !second.EffectiveAuthTime().After(first.EffectiveAuthTime()) {
		t.Fatalf("second login's auth_time %v is not after the first's %v", second.EffectiveAuthTime(), first.EffectiveAuthTime())
	}
	if ok, _ := first.CanBeUsed(time.Now()); !ok {
		t.Fatal("the first session must survive the second login")
	}
}
