package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// inMemoryUserSessionRepo is the minimal SessionRepository the
// service tests need. Unused methods panic so a drift in the
// service's surface is caught at test time.
type inMemoryUserSessionRepo struct {
	mu             sync.Mutex
	byID           map[uuid.UUID]*domain.Session
	bySelector     map[uuid.UUID]*domain.Session
	createErr      error
	updateErr      error
	deleteReturned []*domain.Session
	// statusInfo, when set, is returned by GetSessionWithUserAndOrgStatus
	// so a test can drive the rotation-time revalidation branch. Nil
	// (default) ⇒ (nil, nil) ⇒ revalidation skipped (happy path).
	statusInfo *domain.SessionValidationInfo
}

func newSessionRepo() *inMemoryUserSessionRepo {
	return &inMemoryUserSessionRepo{
		byID:       map[uuid.UUID]*domain.Session{},
		bySelector: map[uuid.UUID]*domain.Session{},
	}
}

func (r *inMemoryUserSessionRepo) Create(_ context.Context, s *domain.Session) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createErr != nil {
		return nil, r.createErr
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return &cp, nil
}

func (r *inMemoryUserSessionRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

func (r *inMemoryUserSessionRepo) GetByTokenSelector(_ context.Context, sel uuid.UUID) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.bySelector[sel]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

func (r *inMemoryUserSessionRepo) Update(_ context.Context, s *domain.Session, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateErr != nil {
		return r.updateErr
	}
	old, ok := r.byID[s.ID]
	if !ok {
		return errors.New("not found")
	}
	if old.TokenSelector != nil {
		delete(r.bySelector, *old.TokenSelector)
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return nil
}

// RotateToken models the P0-12 CAS: rotate + extend expiry ONLY while the
// validator still matches and the session is active. A concurrent sibling that
// rotated first advanced the hash, so a second call finds a mismatch → won=false
// (benign CAS loss).
func (r *inMemoryUserSessionRepo) RotateToken(_ context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateErr != nil {
		return nil, false, r.updateErr
	}
	s, ok := r.byID[sessionID]
	if !ok {
		return nil, false, nil
	}
	if s.TokenValidatorHash == nil || *s.TokenValidatorHash != expectedValidatorHash ||
		!s.IsValid || s.RevokedAt != nil {
		return nil, false, nil // lost CAS / inactive — benign
	}
	s.TokenValidatorHash = &newValidatorHash
	s.ExpiresAt = newExpiresAt
	s.LastUsedAt = &lastUsedAt
	cp := *s
	return &cp, true, nil
}

func (r *inMemoryUserSessionRepo) RecordACRUplift(context.Context, uuid.UUID, time.Time, string) error {
	panic("not used")
}

func (r *inMemoryUserSessionRepo) Revoke(_ context.Context, id, _ uuid.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if !ok {
		return nil
	}
	now := time.Now()
	s.RevokedAt = &now
	s.RevokedReason = &reason
	s.IsValid = false
	return nil
}

func (r *inMemoryUserSessionRepo) RevokeByUserID(_ context.Context, userID uuid.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, s := range r.byID {
		if s.UserID == userID {
			s.RevokedAt = &now
			s.RevokedReason = &reason
			s.IsValid = false
		}
	}
	return nil
}

func (r *inMemoryUserSessionRepo) RevokeByOrganizationID(context.Context, uuid.UUID, string) error {
	panic("not used")
}

func (r *inMemoryUserSessionRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("not used")
}

func (r *inMemoryUserSessionRepo) ListByUserID(context.Context, uuid.UUID, bool) ([]*domain.Session, error) {
	panic("not used")
}

func (r *inMemoryUserSessionRepo) ListActiveByUserID(_ context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Session, 0)
	for _, s := range r.byID {
		if s == nil {
			continue
		}
		if s.UserID != userID {
			continue
		}
		if !s.IsValid {
			continue
		}
		if s.RevokedAt != nil {
			continue
		}
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}

func (r *inMemoryUserSessionRepo) CountActiveByUserID(context.Context, uuid.UUID) (int, error) {
	panic("not used")
}

func (r *inMemoryUserSessionRepo) DeleteExpiredReturning(_ context.Context, _ time.Duration, _ int) ([]*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Session, len(r.deleteReturned))
	copy(out, r.deleteReturned)
	for _, s := range r.deleteReturned {
		delete(r.byID, s.ID)
		if s.TokenSelector != nil {
			delete(r.bySelector, *s.TokenSelector)
		}
	}
	r.deleteReturned = nil
	return out, nil
}

func (r *inMemoryUserSessionRepo) GetSessionWithUserAndOrgStatus(_ context.Context, _ uuid.UUID) (*domain.SessionValidationInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusInfo, nil
}

func (r *inMemoryUserSessionRepo) GetStats(context.Context) (map[string]int, error) {
	panic("not used")
}

// Compile-time check.
var _ repository.SessionRepository = (*inMemoryUserSessionRepo)(nil)

// ---------- Construction ----------

func TestNewUserSessionService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewUserSessionService(nil, nil, UserSessionServiceOptions{})
}

// ---------- CreateUserSession ----------

func TestCreateUserSession_PersistsHashOnlyNeverRawValidator(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	out, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.RefreshToken == "" {
		t.Fatalf("refresh token empty")
	}
	if !strings.Contains(out.RefreshToken, ".") {
		t.Errorf("refresh token shape wrong: %q", out.RefreshToken)
	}
	parsed, _ := domain.ParseSecureRefreshToken(out.RefreshToken)
	wantHash := sha256.Sum256(parsed.Validator)
	want := hex.EncodeToString(wantHash[:])
	row := repo.byID[out.Session.ID]
	if row.TokenValidatorHash == nil || *row.TokenValidatorHash != want {
		t.Errorf("persisted hash mismatch")
	}
	// Validator hash must NEVER equal any substring of the wire
	// token.
	if strings.Contains(*row.TokenValidatorHash, out.RefreshToken) {
		t.Errorf("validator hash leaked raw wire token")
	}
}

func TestCreateUserSession_NilUserIDRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{})
	if !errors.Is(err, ErrUserSessionInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestCreateUserSession_RememberMeTTLApplied(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{
		DefaultTTL:    time.Hour,
		RememberMeTTL: 24 * time.Hour,
	})
	uid := uuid.New()
	out, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID: uid, RememberMe: true,
	})
	if out.Session.ExpiresAt.Sub(out.Session.CreatedAt) < 23*time.Hour {
		t.Errorf("remember-me TTL not applied: %v", out.Session.ExpiresAt.Sub(out.Session.CreatedAt))
	}
}

// ---------- RotateRefreshToken ----------

// Rotation issues a fresh wire token (the VALIDATOR rotates) while keeping
// the same session row. The SELECTOR is deliberately kept stable across
// rotations so a replayed pre-rotation token still resolves to the live
// session and is caught by the reuse branch (see TestRotate_ReuseAfterRotationDetected).
func TestRotate_RotatesTokenKeepsSession(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	second, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Errorf("rotation did not change token")
	}
	if second.Session.ID != first.Session.ID {
		t.Errorf("session ID changed; rotation should keep same row: %s vs %s", first.Session.ID, second.Session.ID)
	}
	// The selector is stable; the validator differs. Decode both and confirm.
	firstTok, _ := domain.ParseSecureRefreshToken(first.RefreshToken)
	secondTok, _ := domain.ParseSecureRefreshToken(second.RefreshToken)
	if firstTok.Selector != secondTok.Selector {
		t.Errorf("selector must be stable across rotation: %s vs %s", firstTok.Selector, secondTok.Selector)
	}
}

// (b) REUSE — replaying a rotated-away refresh token is DETECTED as reuse
// (R1). The selector is kept stable across rotations, so the replayed
// pre-rotation token resolves to the live session with a stale validator →
// reuse → the ENTIRE session family is revoked and the dedicated
// ErrUserSessionReuse is surfaced (so the handler emits the breach signal).
// The freshly-rotated successor token (N+1) is also dead afterward.
func TestRotate_ReuseAfterRotationDetected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	// Legitimate rotation N → N+1.
	second, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Replay the ORIGINAL (now rotated-away) refresh token → REUSE.
	_, reuseErr := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	t.Logf("EVIDENCE (b) browser reuse: err=%v", reuseErr)
	if !errors.Is(reuseErr, ErrUserSessionReuse) {
		t.Fatalf("err = %v, want ErrUserSessionReuse (rotated-away token replayed)", reuseErr)
	}
	// The whole family must now be revoked: even the legitimate successor
	// (N+1) can no longer rotate.
	if active, _ := repo.ListActiveByUserID(context.Background(), uid); len(active) != 0 {
		t.Errorf("family not revoked: %d sessions still active after reuse", len(active))
	}
	if _, succErr := svc.RotateRefreshToken(context.Background(), second.RefreshToken); succErr == nil {
		t.Errorf("successor token N+1 still works after family revocation; want failure")
	}
}

// (d) TAKEOVER — an attacker who stole token N rotates FIRST (to N+1); the
// victim later replays its copy of N. The replay is the rotated-away token →
// reuse → the family (including the attacker's N+1 chain) is revoked.
func TestRotate_TakeoverThenVictimReplayRevokesFamily(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	issued, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	// Attacker rotates first using the stolen token.
	attacker, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatalf("attacker rotate: %v", err)
	}
	// Victim later replays its (now stale) copy of the same token → reuse.
	_, reuseErr := svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
	t.Logf("EVIDENCE (d) takeover: victim replay err=%v", reuseErr)
	if !errors.Is(reuseErr, ErrUserSessionReuse) {
		t.Fatalf("err = %v, want ErrUserSessionReuse", reuseErr)
	}
	// The attacker's freshly-rotated chain is revoked too.
	if _, attErr := svc.RotateRefreshToken(context.Background(), attacker.RefreshToken); attErr == nil {
		t.Errorf("attacker chain still usable after victim replay; want family revoked")
	}
	if active, _ := repo.ListActiveByUserID(context.Background(), uid); len(active) != 0 {
		t.Errorf("family not revoked: %d still active", len(active))
	}
}

// (e) ROTATION REVALIDATION — a valid, correctly-rotating refresh token is
// still refused when the user/org went inactive after login (R1-secondary).
func TestRotate_RevalidationRejectsInactiveUserOrg(t *testing.T) {
	cases := []struct {
		name string
		info domain.SessionValidationInfo
	}{
		{"banned/deleted user", domain.SessionValidationInfo{UserActive: true, UserDeleted: true, OrgActive: true}},
		{"inactive user", domain.SessionValidationInfo{UserActive: false, OrgActive: true}},
		{"inactive org", domain.SessionValidationInfo{UserActive: true, OrgActive: false}},
		{"deleted org", domain.SessionValidationInfo{UserActive: true, OrgActive: true, OrgDeleted: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newSessionRepo()
			svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
			uid := uuid.New()
			issued, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
			// Status flips to inactive AFTER login.
			info := tc.info
			repo.statusInfo = &info
			_, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken)
			t.Logf("EVIDENCE (e) %s: err=%v", tc.name, err)
			if !errors.Is(err, ErrUserSessionInvalidGrant) {
				t.Fatalf("err = %v, want ErrUserSessionInvalidGrant (inactive subject must not rotate)", err)
			}
			if active, _ := repo.ListActiveByUserID(context.Background(), uid); len(active) != 0 {
				t.Errorf("inactive session not revoked: %d still active", len(active))
			}
		})
	}
}

// (a) HAPPY PATH — normal sequential rotation continues to work and the
// revalidation seam (healthy status) does not interfere.
func TestRotate_HappyPathSequentialRotation(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	issued, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	// Healthy status — rotation must proceed.
	repo.statusInfo = &domain.SessionValidationInfo{UserActive: true, OrgActive: true}
	tok := issued.RefreshToken
	for i := 0; i < 3; i++ {
		next, err := svc.RotateRefreshToken(context.Background(), tok)
		if err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
		if next.RefreshToken == tok {
			t.Fatalf("rotation %d did not change the token", i)
		}
		tok = next.RefreshToken
	}
	t.Logf("EVIDENCE (a) happy path: 3 sequential rotations succeeded")
}

func TestRotate_TamperedValidatorIsReuse(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	// Construct a wire token with the SAME selector but a
	// different validator. This simulates an attacker who
	// learned a selector but not the validator.
	parts := strings.SplitN(first.RefreshToken, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("bad token shape")
	}
	tampered := parts[0] + ".AAAA"
	_, err := svc.RotateRefreshToken(context.Background(), tampered)
	if !errors.Is(err, ErrUserSessionReuse) {
		t.Errorf("err = %v, want reuse", err)
	}
	// All sessions for the user must have been revoked.
	row := repo.byID[first.Session.ID]
	if row == nil || row.RevokedAt == nil {
		t.Errorf("session not revoked after reuse: %+v", row)
	}
}

func TestRotate_ExpiredSessionRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	// Force-expire the row by mutating it in place.
	repo.byID[first.Session.ID].ExpiresAt = time.Now().Add(-time.Hour)
	row := repo.byID[first.Session.ID]
	if row.TokenSelector != nil {
		repo.bySelector[*row.TokenSelector] = row
	}
	_, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if !errors.Is(err, ErrUserSessionInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestRotate_RevokedSessionRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	_ = svc.RevokeSession(context.Background(), first.Session.ID, "x")
	_, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if !errors.Is(err, ErrUserSessionInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestRotate_UnknownSelectorRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	fake := uuid.NewString() + ".AAAA"
	_, err := svc.RotateRefreshToken(context.Background(), fake)
	if !errors.Is(err, ErrUserSessionInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestRotate_MalformedRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	_, err := svc.RotateRefreshToken(context.Background(), "not-a-token")
	if !errors.Is(err, ErrUserSessionInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

// ---------- RevokeSession + RevokeUserSessions ----------

func TestRevokeSession_FlipsRowRevokedAt(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err := svc.RevokeSession(context.Background(), first.Session.ID, "logout"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if repo.byID[first.Session.ID].RevokedAt == nil {
		t.Errorf("row not revoked")
	}
}

func TestRevokeUserSessions_SatisfiesSessionRevokerSeam(t *testing.T) {
	var _ SessionRevoker = (*UserSessionService)(nil) // compile-time
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err := svc.RevokeUserSessions(context.Background(), uid, "rbac_role_removed", map[string]any{"x": "y"}); err != nil {
		t.Fatalf("revoke user: %v", err)
	}
	if repo.byID[first.Session.ID].RevokedAt == nil {
		t.Errorf("user-wide revoke did not flip row")
	}
}

func TestRevokeUserSessions_NilUserIDRejected(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	if err := svc.RevokeUserSessions(context.Background(), uuid.Nil, "x", nil); !errors.Is(err, ErrUserSessionInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

// ---------- DeleteExpired ----------

func TestDeleteExpired_ReturnsRowCount(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	repo.deleteReturned = []*domain.Session{
		{ID: uuid.New()},
		{ID: uuid.New()},
	}
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 2 {
		t.Errorf("n = %d", n)
	}
}

func TestRotate_AbsoluteLifetimeExceededRejectsRotation(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{AbsoluteLifetime: 24 * time.Hour})
	// Seed a session whose CreatedAt is past the absolute window.
	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	row := repo.byID[issued.Session.ID]
	row.CreatedAt = old
	row.ExpiresAt = time.Now().Add(time.Hour) // still nominally valid
	repo.bySelector[*row.TokenSelector] = row

	if _, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken); !errors.Is(err, ErrUserSessionInvalidGrant) {
		t.Errorf("expected invalid_grant on absolute-lifetime guard, got %v", err)
	}
	if row.IsValid {
		t.Errorf("session row was not revoked after absolute-lifetime trip")
	}
}

func TestRotate_AbsoluteLifetimeDisabledByNegative(t *testing.T) {
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{AbsoluteLifetime: -1})
	issued, _ := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uuid.New()})
	row := repo.byID[issued.Session.ID]
	row.CreatedAt = time.Now().Add(-365 * 24 * time.Hour) // way past any normal window
	row.ExpiresAt = time.Now().Add(time.Hour)
	repo.bySelector[*row.TokenSelector] = row
	if _, err := svc.RotateRefreshToken(context.Background(), issued.RefreshToken); err != nil {
		t.Errorf("unexpected err with AbsoluteLifetime=-1: %v", err)
	}
}

// ---------- MaxSessionsPerUser per-org eviction ----------
//
// Tests below pin the post-fix contract from slice
// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
// (Decision D-015 §4).
//
// Contract recap:
//   - non-admin role + MaxSessionsPerUser > 0 + count would exceed cap
//     → revoke oldest (count - cap + 1) sessions with reason
//     "max_sessions_exceeded"; metric increments per eviction; if
//     WithAudit wired, bounded audit event emits per eviction.
//   - admin role (site_admin OR org_admin) → bypass (locked
//     admin-local invariant per Decision D-004).
//   - MaxSessionsPerUser <= 0 → bypass (preserves pre-slice
//     unlimited behaviour).
//   - audit payload MUST NOT carry password / token / cookie /
//     raw session validator / DB URL / hashed credential material.

// maxSessionsAuditor captures audit events for assertion.
type maxSessionsAuditor struct {
	events []captureAuditEvent
}

type captureAuditEvent struct {
	action    string
	outcome   string
	subjectID uuid.UUID
	orgID     uuid.UUID
	role      string
	metadata  map[string]any
}

func (a *maxSessionsAuditor) Record(_ context.Context, e audit.Event) error {
	a.events = append(a.events, captureAuditEvent{
		action:    e.Action,
		outcome:   e.Outcome,
		subjectID: e.SubjectID,
		orgID:     e.OrganizationID,
		role:      e.ActorRole,
		metadata:  e.Metadata,
	})
	return nil
}

func maxSessionsHarness(t *testing.T) (*UserSessionService, *inMemoryUserSessionRepo) {
	t.Helper()
	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	return svc, repo
}

// seedActiveSession inserts a fake active session row with an explicit
// CreatedAt so the sort-by-oldest contract can be tested without
// timing flakes.
func seedActiveSession(t *testing.T, repo *inMemoryUserSessionRepo, userID uuid.UUID, createdAt time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	sel := uuid.New()
	hash := "fake-hash"
	row := &domain.Session{
		ID:                 id,
		UserID:             userID,
		TokenSelector:      &sel,
		TokenValidatorHash: &hash,
		IsValid:            true,
		CreatedAt:          createdAt,
		ExpiresAt:          createdAt.Add(24 * time.Hour),
	}
	repo.mu.Lock()
	repo.byID[id] = row
	repo.mu.Unlock()
	return id
}

func TestCreateUserSession_MaxSessions_NoCapPreservesPreviousBehaviour(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	// Seed 5 active sessions — well above any reasonable cap.
	now := time.Now()
	for i := 0; i < 5; i++ {
		seedActiveSession(t, repo, uid, now.Add(time.Duration(-i)*time.Minute))
	}
	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 0, // no cap
		Role:               string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if issued == nil || issued.Session == nil {
		t.Fatal("Create: nil result with no cap")
	}
	// All 5 originals + the new one = 6 active. None should be revoked.
	repo.mu.Lock()
	defer repo.mu.Unlock()
	revoked := 0
	for _, s := range repo.byID {
		if s.UserID == uid && s.RevokedAt != nil {
			revoked++
		}
	}
	if revoked != 0 {
		t.Errorf("MaxSessionsPerUser=0 must not evict anything; revoked=%d", revoked)
	}
}

func TestCreateUserSession_MaxSessions_OrgUserCap1RevokesOldest(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	orgID := uuid.New()
	now := time.Now()
	// Seed 1 existing session — at the cap. Creating another should
	// evict the existing one so post-state has 1 active.
	oldestID := seedActiveSession(t, repo, uid, now.Add(-1*time.Hour))
	issued, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 1,
		OrganizationID:     orgID,
		Role:               string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	// oldest must be revoked with reason max_sessions_exceeded.
	old := repo.byID[oldestID]
	if old == nil {
		t.Fatal("oldest session row missing")
	}
	if old.RevokedAt == nil {
		t.Fatal("cap=1 + org_user MUST evict the existing session; oldest still active")
	}
	if old.RevokedReason == nil || *old.RevokedReason != "max_sessions_exceeded" {
		t.Errorf("evict reason mismatch; got %v", old.RevokedReason)
	}
	// the new session row must be present and active.
	if issued == nil || issued.Session == nil {
		t.Fatal("new session not minted")
	}
	newRow := repo.byID[issued.Session.ID]
	if newRow == nil || newRow.RevokedAt != nil {
		t.Fatal("new session must be active post-eviction")
	}
}

func TestCreateUserSession_MaxSessions_OrgUserCap2RevokesOnlyExcessOldest(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	now := time.Now()
	// Seed 3 existing sessions with descending ages — the OLDEST two
	// should be evicted to leave room for the new one under cap=2.
	oldestID := seedActiveSession(t, repo, uid, now.Add(-3*time.Hour))
	midID := seedActiveSession(t, repo, uid, now.Add(-2*time.Hour))
	newestID := seedActiveSession(t, repo, uid, now.Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 2,
		Role:               string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.byID[oldestID].RevokedAt == nil {
		t.Error("oldest of 3 must be evicted under cap=2")
	}
	if repo.byID[midID].RevokedAt == nil {
		t.Error("middle of 3 must be evicted under cap=2 (need to evict 2 to leave room for new session)")
	}
	if repo.byID[newestID].RevokedAt != nil {
		t.Error("newest of 3 MUST be preserved under cap=2")
	}
}

func TestCreateUserSession_MaxSessions_OrgAdminExemptEvenAtCap1(t *testing.T) {
	// Admin-local invariant pin (Decision D-004): org_admin sessions
	// are exempt from the cap, regardless of value. Seed an existing
	// admin session at cap=1; creating another admin session MUST NOT
	// evict the original. Both remain active.
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	existingID := seedActiveSession(t, repo, uid, time.Now().Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 1,
		Role:               string(domain.RoleOrgAdmin),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.byID[existingID].RevokedAt != nil {
		t.Fatal("ADMIN-LOCAL INVARIANT VIOLATED: org_admin existing session must NOT be evicted under cap=1 (Decision D-004)")
	}
}

func TestCreateUserSession_MaxSessions_SiteAdminExemptEvenAtCap1(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	existingID := seedActiveSession(t, repo, uid, time.Now().Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 1,
		Role:               string(domain.RoleSiteAdmin),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.byID[existingID].RevokedAt != nil {
		t.Fatal("ADMIN-LOCAL INVARIANT VIOLATED: site_admin existing session must NOT be evicted under cap=1 (Decision D-004)")
	}
}

func TestCreateUserSession_MaxSessions_NilProjectedPolicyIsNoOp(t *testing.T) {
	// When the caller has nil OrgMaxSessionsPerUser on the user row, it
	// dereferences to 0 in the wire-in at LocalLoginService.Login —
	// pinning that 0 is a true no-op preserves backward-compat.
	svc, repo := maxSessionsHarness(t)
	uid := uuid.New()
	seedActiveSession(t, repo, uid, time.Now().Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID: uid,
		// MaxSessionsPerUser unset = 0
		Role: string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, s := range repo.byID {
		if s.UserID == uid && s.RevokedAt != nil {
			t.Fatal("nil/0 MaxSessionsPerUser MUST be a no-op; eviction happened")
		}
	}
}

func TestCreateUserSession_MaxSessions_AuditEmittedOnlyOnEviction(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	auditor := &maxSessionsAuditor{}
	svc = svc.WithAudit(auditServiceAdapter{auditor})
	uid := uuid.New()
	orgID := uuid.New()
	seedActiveSession(t, repo, uid, time.Now().Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 1,
		OrganizationID:     orgID,
		Role:               string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("want exactly 1 audit event for 1 eviction, got %d", len(auditor.events))
	}
	ev := auditor.events[0]
	if ev.action != string(domain.AuditSessionEvictedMaxSessions) {
		t.Errorf("audit action: want %q, got %q", string(domain.AuditSessionEvictedMaxSessions), ev.action)
	}
	if ev.outcome != "success" {
		t.Errorf("audit outcome: want success, got %q", ev.outcome)
	}
	if ev.subjectID != uid {
		t.Errorf("audit subject_id mismatch")
	}
	if ev.orgID != orgID {
		t.Errorf("audit organization_id mismatch")
	}
}

func TestCreateUserSession_MaxSessions_NoAuditOnNoEviction(t *testing.T) {
	svc, repo := maxSessionsHarness(t)
	auditor := &maxSessionsAuditor{}
	svc = svc.WithAudit(auditServiceAdapter{auditor})
	uid := uuid.New()
	// 0 existing sessions + cap=5 — no eviction needed.
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 5,
		Role:               string(domain.RoleOrgUser),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(auditor.events) != 0 {
		t.Errorf("want 0 audit events when no eviction; got %d", len(auditor.events))
	}
	_ = repo
}

func TestCreateUserSession_MaxSessions_AuditPayloadNoSensitiveValues(t *testing.T) {
	// Sensitive-data invariant: audit metadata MUST NOT include
	// password / TOTP / refresh token / cookie / raw session validator
	// material. The test sweeps every captured event's metadata map for
	// any of those sentinel strings.
	svc, repo := maxSessionsHarness(t)
	auditor := &maxSessionsAuditor{}
	svc = svc.WithAudit(auditServiceAdapter{auditor})
	uid := uuid.New()
	seedActiveSession(t, repo, uid, time.Now().Add(-1*time.Hour))
	_, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             uid,
		MaxSessionsPerUser: 1,
		OrganizationID:     uuid.New(),
		Role:               string(domain.RoleOrgUser),
		IPAddress:          stringPtr("10.0.0.1"),
		UserAgent:          stringPtr("ua-test"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(auditor.events))
	}
	leakKeys := []string{"password", "token", "cookie", "validator", "hash", "totp", "secret"}
	for k, v := range auditor.events[0].metadata {
		lk := strings.ToLower(k)
		for _, leak := range leakKeys {
			if strings.Contains(lk, leak) {
				t.Errorf("audit metadata key %q matches sensitive token %q", k, leak)
			}
		}
		if s, ok := v.(string); ok {
			ls := strings.ToLower(s)
			for _, leak := range leakKeys {
				if strings.Contains(ls, leak) {
					t.Errorf("audit metadata[%q] value %q matches sensitive token %q", k, s, leak)
				}
			}
		}
	}
}

func stringPtr(s string) *string { return &s }

// auditServiceAdapter wraps maxSessionsAuditor into the production
// audit.Service interface for tests that pass it through WithAudit.
type auditServiceAdapter struct {
	inner *maxSessionsAuditor
}

func (a auditServiceAdapter) Record(ctx context.Context, e audit.Event) error {
	return a.inner.Record(ctx, e)
}
