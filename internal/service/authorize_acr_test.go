package service

// authorize_acr_test.go — THE-HONEST-ACR: acr_values is honored, never
// faked. The authorize gate decides between mint / step-up / unmet from the
// session's EFFECTIVE acr and the user's TOTP enrolment; the acr a token
// carries is always Session.EffectiveACR (see id_token_acr_test.go).

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakeAuthorizeUserLookup struct{ user *domain.User }

func (f *fakeAuthorizeUserLookup) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.user == nil || f.user.ID != id {
		return nil, errors.New("not found")
	}
	return f.user, nil
}

// acrHarness: a live password-rung session for a principal, plus a user row
// enrolled (or not) in TOTP.
func acrHarness(t *testing.T, sessionACR string, mfaEnrolled bool) (*AuthorizeService, *inMemoryAuthCodeRepo, *domain.Principal) {
	t.Helper()
	svc, repo, sess := newAuthorizeHarness(t, true)
	principal := authorizePrincipal(sess.session.ID)
	sess.session.UserID = principal.UserID
	sess.session.Acr = sessionACR
	svc.WithUserLookup(&fakeAuthorizeUserLookup{user: &domain.User{ID: principal.UserID, MFAEnabled: mfaEnrolled}})
	return svc, repo, principal
}

func authorizeWithACR(t *testing.T, svc *AuthorizeService, principal *domain.Principal, acrValues string) (*AuthorizeResult, error) {
	t.Helper()
	_, challenge := authorizeChallenge(t)
	req := newAuthorizeRequest(challenge, principal)
	req.AcrValues = acrValues
	return svc.Authorize(context.Background(), req)
}

// RULE: ACR-HONEST-1 — a requested acr the session did not perform never
// lands: the TOTP rung requested on a password-rung session yields a
// step-up (enrolled) or the honest unmet error (not enrolled); zero codes.
func TestAuthorize_ACRValues_AboveSessionNeverMintsUnperformed(t *testing.T) {
	t.Run("TOTP enrolled → step-up, no code", func(t *testing.T) {
		svc, repo, principal := acrHarness(t, auth.ACRPassword, true)
		res, err := authorizeWithACR(t, svc, principal, auth.ACRMFA)
		if !errors.Is(err, ErrAuthorizeStepUpRequired) {
			t.Fatalf("err = %v (res=%v), want ErrAuthorizeStepUpRequired", err, res)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("%d code(s) minted for an unperformed acr, want 0", len(repo.byID))
		}
	})
	t.Run("TOTP not enrolled → unmet_authentication_requirements, no code", func(t *testing.T) {
		svc, repo, principal := acrHarness(t, auth.ACRPassword, false)
		_, err := authorizeWithACR(t, svc, principal, auth.ACRMFA)
		if !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("err = %v, want ErrAuthorizeUnmetAuthenticationRequirements", err)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("%d code(s) minted, want 0", len(repo.byID))
		}
	})
	t.Run("no user lookup wired → unmet (never a guess)", func(t *testing.T) {
		svc, repo, sess := newAuthorizeHarness(t, true)
		sess.session.Acr = auth.ACRPassword
		principal := authorizePrincipal(sess.session.ID)
		if _, err := authorizeWithACR(t, svc, principal, auth.ACRMFA); !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("err = %v, want ErrAuthorizeUnmetAuthenticationRequirements", err)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("%d code(s) minted, want 0", len(repo.byID))
		}
	})
	t.Run("phishing-resistant rung has no ceremony → unmet even when enrolled", func(t *testing.T) {
		svc, repo, principal := acrHarness(t, auth.ACRPassword, true)
		if _, err := authorizeWithACR(t, svc, principal, auth.ACRPhishingResistant); !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("err = %v, want ErrAuthorizeUnmetAuthenticationRequirements", err)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("%d code(s) minted, want 0", len(repo.byID))
		}
	})
}

// The performed context satisfies the request (any-of, by rank).
func TestAuthorize_ACRValues_PerformedContextMints(t *testing.T) {
	cases := []struct {
		name, sessionACR, requested string
	}{
		{"suite shape: both advertised rungs requested, password session", auth.ACRPassword, auth.ACRPassword + " " + auth.ACRMFA},
		{"password requested, password session", auth.ACRPassword, auth.ACRPassword},
		{"password requested, TOTP session (higher rank meets)", auth.ACRMFA, auth.ACRPassword},
		{"TOTP requested, TOTP session", auth.ACRMFA, auth.ACRMFA},
		{"unknown values only are ignored (voluntary)", auth.ACRPassword, "1 2 urn:example:gold"},
		{"unknown + known: the known one decides", auth.ACRPassword, "urn:example:gold " + auth.ACRPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, principal := acrHarness(t, tc.sessionACR, false)
			res, err := authorizeWithACR(t, svc, principal, tc.requested)
			if err != nil {
				t.Fatalf("err = %v, want a minted code", err)
			}
			if res == nil || res.Code == "" || len(repo.byID) != 1 {
				t.Fatalf("res=%+v codes=%d, want exactly one code", res, len(repo.byID))
			}
		})
	}
}

// A step-up that was PERFORMED (LastACRUpliftValue written) satisfies the
// TOTP rung on the same session.
func TestAuthorize_ACRValues_RecordedUpliftSatisfies(t *testing.T) {
	svc, repo, sess := newAuthorizeHarness(t, true)
	principal := authorizePrincipal(sess.session.ID)
	sess.session.Acr = auth.ACRPassword
	sess.session.RecordACRUplift(sess.session.CreatedAt, auth.ACRMFA)
	if _, err := authorizeWithACR(t, svc, principal, auth.ACRMFA); err != nil {
		t.Fatalf("err = %v, want mint after a recorded uplift", err)
	}
	if len(repo.byID) != 1 {
		t.Fatalf("codes=%d, want 1", len(repo.byID))
	}
}

// A legacy session with no acr (pre-stamping) asked for the password rung
// cannot prove it: re-authentication (login_required), which stamps the
// level honestly. Never a code with a guessed acr.
func TestAuthorize_ACRValues_UnstampedSessionRequiresLogin(t *testing.T) {
	svc, repo, principal := acrHarness(t, "", false)
	if _, err := authorizeWithACR(t, svc, principal, auth.ACRPassword); !errors.Is(err, ErrAuthorizeLoginRequired) {
		t.Fatalf("err = %v, want ErrAuthorizeLoginRequired", err)
	}
	if len(repo.byID) != 0 {
		t.Fatalf("codes=%d, want 0", len(repo.byID))
	}
}

// Without acr_values nothing changes: an unstamped session still mints
// (voluntary claim not requested).
func TestAuthorize_NoACRValues_UnstampedSessionMints(t *testing.T) {
	svc, repo, principal := acrHarness(t, "", false)
	if _, err := authorizeWithACR(t, svc, principal, ""); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(repo.byID) != 1 {
		t.Fatalf("codes=%d, want 1", len(repo.byID))
	}
}
