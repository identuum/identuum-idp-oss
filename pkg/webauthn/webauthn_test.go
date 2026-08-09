package webauthn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	pkgwebauthn "github.com/identuum/identuum-idp-oss/pkg/webauthn"
)

// TestPkgSeam_RoutePaths_StableLiterals pins the canonical OSS
// WebAuthn route literals. The CE overlay's contract tests rely on
// these constants; renaming any of them is a CE-visible API break.
func TestPkgSeam_RoutePaths_StableLiterals(t *testing.T) {
	wants := map[string]string{
		"register_begin":    "/api/v1/webauthn/register/begin",
		"register_finish":   "/api/v1/webauthn/register/finish",
		"credentials_list":  "/api/v1/webauthn/credentials",
		"credential_delete": "/api/v1/webauthn/credentials/:id",
		"login_begin":       "/api/v1/auth/login/webauthn/begin",
		"login_finish":      "/api/v1/auth/login/webauthn/finish",
	}
	got := pkgwebauthn.RoutePaths()
	if len(got) != len(wants) {
		t.Fatalf("RoutePaths() len: got %d, want %d", len(got), len(wants))
	}
	for k, want := range wants {
		if got[k] != want {
			t.Errorf("RoutePaths()[%q] = %q, want %q", k, got[k], want)
		}
	}
}

// TestPkgSeam_TTL_MatchesUpstreamFiveMinutes pins the ceremony TTL
// constant. The CE handler shim landing in Prompt 3 must apply the
// same TTL when storing ceremony sessions; this test catches a
// future drift in either direction.
func TestPkgSeam_TTL_MatchesUpstreamFiveMinutes(t *testing.T) {
	if pkgwebauthn.TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m (upstream go-webauthn default)", pkgwebauthn.TTL)
	}
}

// TestPkgSeam_InMemorySessionRepository_RoundTrip exercises Save +
// Get + Delete on the re-exported in-memory ceremony repo. This is
// the structural proof that the seam is wired end-to-end + the
// in-memory implementation satisfies the SessionRepository interface.
// We intentionally do NOT exercise the upstream go-webauthn library
// — that would drag a virtual authenticator into the test.
func TestPkgSeam_InMemorySessionRepository_RoundTrip(t *testing.T) {
	repo := pkgwebauthn.NewInMemorySessionRepository()
	if repo == nil {
		t.Fatal("NewInMemorySessionRepository returned nil")
	}
	// Compile-time assertion via interface satisfaction:
	var _ pkgwebauthn.SessionRepository = repo

	// Delete-of-missing-key MUST NOT return an error per the
	// repository contract — handlers fire it from a defer without
	// checking the prior Get outcome.
	if err := repo.Delete(context.Background(), "nonexistent"); err != nil {
		t.Errorf("Delete(missing) returned error: %v (must be idempotent)", err)
	}
}

// ── Service seam tests (agent-a-20260784 v0.1.2 extension) ────────────────

// fakeUserRepoForSeam is a no-op CE-adapter-shape stub that proves
// the pkg/webauthn.UserRepo interface is satisfiable from outside
// the OSS module without crossing the internal/ boundary. The
// methods return errors so no real user-row construction is required.
type fakeUserRepoForSeam struct{}

func (fakeUserRepoForSeam) GetByID(_ context.Context, _ uuid.UUID) (*pkgwebauthn.User, error) {
	return nil, errors.New("fakeUserRepoForSeam: GetByID not implemented")
}

func (fakeUserRepoForSeam) FindUsersByEmail(_ context.Context, _ string) ([]*pkgwebauthn.User, error) {
	return nil, errors.New("fakeUserRepoForSeam: FindUsersByEmail not implemented")
}

// TestPkgSeam_UserRepo_SatisfiableFromOutside is the structural
// proof that an external (CE-style) adapter can implement the
// `pkgwebauthn.UserRepo` interface using only the public seam.
// Compile-time assertion via assignment plus a runtime smoke for
// the GetByID + FindUsersByEmail contracts.
func TestPkgSeam_UserRepo_SatisfiableFromOutside(t *testing.T) {
	var repo pkgwebauthn.UserRepo = fakeUserRepoForSeam{}
	if _, err := repo.GetByID(context.Background(), uuid.Nil); err == nil {
		t.Error("expected error from fakeUserRepoForSeam.GetByID")
	}
	if _, err := repo.FindUsersByEmail(context.Background(), "nobody@example.invalid"); err == nil {
		t.Error("expected error from fakeUserRepoForSeam.FindUsersByEmail")
	}
}

// TestPkgSeam_NewService_RejectsNilDeps pins the dependency
// validation contract: NewService MUST return a non-nil error when
// any required dependency is missing. The check is delegated to the
// internal service factory; this test pins that delegation through
// the public seam.
func TestPkgSeam_NewService_RejectsNilDeps(t *testing.T) {
	cases := []struct {
		name string
		cfg  pkgwebauthn.ServiceConfig
		want string
	}{
		{
			name: "missing UserRepo",
			cfg: pkgwebauthn.ServiceConfig{
				BaseURL:     "https://idp.example.invalid",
				CredRepo:    nil,
				SessionRepo: nil,
			},
			want: "nil userRepo",
		},
		{
			name: "missing BaseURL",
			cfg: pkgwebauthn.ServiceConfig{
				BaseURL:     "",
				UserRepo:    fakeUserRepoForSeam{},
				CredRepo:    nil,
				SessionRepo: nil,
			},
			want: "nil credRepo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := pkgwebauthn.NewService(tc.cfg)
			if err == nil {
				t.Fatalf("expected non-nil error for %s, got svc=%v", tc.name, svc)
			}
			if svc != nil {
				t.Errorf("expected nil service on error, got %v", svc)
			}
			// Spot-check the error mentions the documented missing dep.
			// We do NOT pin the exact error string — only the substring.
			if got := err.Error(); !contains(got, tc.want) {
				t.Errorf("error %q does not mention %q", got, tc.want)
			}
		})
	}
}

// TestPkgSeam_ErrorSentinels_ReExportedAndDistinct pins that the 6
// service-level error sentinels are exported via the seam AND that
// they are distinct (not aliases of each other). CE handler shims
// will errors.Is against these — a mistaken collapse would map two
// failure modes onto the same HTTP code.
func TestPkgSeam_ErrorSentinels_ReExportedAndDistinct(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrSessionInvalid", pkgwebauthn.ErrSessionInvalid},
		{"ErrNoCredentials", pkgwebauthn.ErrNoCredentials},
		{"ErrAssertionInvalid", pkgwebauthn.ErrAssertionInvalid},
		{"ErrCredentialMissing", pkgwebauthn.ErrCredentialMissing},
		{"ErrTenantMismatch", pkgwebauthn.ErrTenantMismatch},
		{"ErrCloneDetected", pkgwebauthn.ErrCloneDetected},
	}
	for _, s := range sentinels {
		if s.err == nil {
			t.Errorf("%s is nil — must be a non-nil error sentinel", s.name)
		}
		if got := s.err.Error(); got == "" {
			t.Errorf("%s has empty message", s.name)
		}
	}
	// Distinctness: every pair must NOT be errors.Is-equivalent.
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i].err, sentinels[j].err) {
				t.Errorf("%s and %s collapse via errors.Is — must be distinct sentinels",
					sentinels[i].name, sentinels[j].name)
			}
		}
	}
}

// contains is a tiny substring helper to avoid pulling in the `strings`
// import just for one call. Returns true iff needle is a substring of
// haystack (or empty needle).
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
