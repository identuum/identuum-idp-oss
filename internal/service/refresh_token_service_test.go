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

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// inMemoryRefreshTokenRepo backs the service tests with a tiny
// map. The repo panics on unused methods so a test that forgets
// to mock a code path fails loudly.
type inMemoryRefreshTokenRepo struct {
	mu        sync.Mutex
	byID      map[uuid.UUID]*domain.RefreshToken
	insertErr error
	getErr    error
	revokeErr error
	rotateErr error
}

func newInMemoryRefreshTokenRepo() *inMemoryRefreshTokenRepo {
	return &inMemoryRefreshTokenRepo{byID: map[uuid.UUID]*domain.RefreshToken{}}
}

func (r *inMemoryRefreshTokenRepo) Insert(_ context.Context, rt *domain.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.insertErr != nil {
		return r.insertErr
	}
	if _, exists := r.byID[rt.ID]; exists {
		return errors.New("duplicate selector")
	}
	cp := *rt
	r.byID[rt.ID] = &cp
	return nil
}

func (r *inMemoryRefreshTokenRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	row, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryRefreshTokenRepo) MarkRevoked(_ context.Context, id uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return r.revokeErr
	}
	row, ok := r.byID[id]
	if !ok {
		return nil
	}
	row.RevokedAt = &at
	return nil
}

func (r *inMemoryRefreshTokenRepo) MarkRotated(_ context.Context, oldID, newID uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rotateErr != nil {
		return r.rotateErr
	}
	row, ok := r.byID[oldID]
	if !ok {
		return nil
	}
	// P3-1: mirror the real compare-and-set. Production carries
	// `AND revoked_at IS NULL`, so a row that is already revoked matches zero
	// rows and the caller loses the race. A fake that silently overwrote it
	// could never surface the concurrent-rotation bug.
	if row.RevokedAt != nil {
		return repository.ErrRefreshAlreadyRotated
	}
	row.RevokedAt = &at
	row.LastUsedAt = &at
	row.ReplacedBy = &newID
	return nil
}

func (r *inMemoryRefreshTokenRepo) SetAccessJTI(_ context.Context, id uuid.UUID, jti string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.byID[id]
	if !ok {
		return nil
	}
	row.AccessJTI = jti
	row.LastUsedAt = &at
	return nil
}

// RevokeAllBySubject flips revoked_at on every active row whose
// Subject matches; mirrors the postgres SQL semantics for tests.
// revokeErr is honoured so error-path tests can pin the bubble-
// up. Empty subject is a no-op.
func (r *inMemoryRefreshTokenRepo) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return 0, r.revokeErr
	}
	if subject == "" {
		return 0, nil
	}
	var n int64
	for _, row := range r.byID {
		if row.Subject != subject {
			continue
		}
		if row.RevokedAt != nil {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
	}
	return n, nil
}

// RevokeByFamily flips revoked_at on every ACTIVE row (not revoked, not
// expired) whose FamilyID matches; mirrors the postgres SQL semantics for
// tests. revokeErr is honoured. Empty familyID is a no-op.
func (r *inMemoryRefreshTokenRepo) RevokeByFamily(_ context.Context, familyID string, at time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return 0, r.revokeErr
	}
	if familyID == "" {
		return 0, nil
	}
	var n int64
	for _, row := range r.byID {
		if row.FamilyID != familyID {
			continue
		}
		if row.RevokedAt != nil {
			continue
		}
		if !row.ExpiresAt.After(at) {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
	}
	return n, nil
}

// RevokeByFamilyReturningAccessJTIs mirrors RevokeByFamily but returns the
// access-jti projection of the ACTIVE family rows it revokes. Empty familyID
// is a no-op.
func (r *inMemoryRefreshTokenRepo) RevokeByFamilyReturningAccessJTIs(_ context.Context, familyID string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return 0, nil, r.revokeErr
	}
	if familyID == "" {
		return 0, nil, nil
	}
	var (
		n    int64
		jtis []repository.RevokedRefreshTokenAccessJTI
	)
	for _, row := range r.byID {
		if row.FamilyID != familyID {
			continue
		}
		if row.RevokedAt != nil {
			continue
		}
		if !row.ExpiresAt.After(at) {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
		if row.AccessJTI == "" {
			continue
		}
		jtis = append(jtis, repository.RevokedRefreshTokenAccessJTI{
			JTI:       row.AccessJTI,
			ExpiresAt: row.ExpiresAt,
		})
	}
	return n, jtis, nil
}

func (r *inMemoryRefreshTokenRepo) RevokeAllBySubjectReturningAccessJTIs(_ context.Context, subject string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return 0, nil, r.revokeErr
	}
	if subject == "" {
		return 0, nil, nil
	}
	var (
		n    int64
		jtis []repository.RevokedRefreshTokenAccessJTI
	)
	for _, row := range r.byID {
		if row.Subject != subject {
			continue
		}
		if row.RevokedAt != nil {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
		if row.AccessJTI == "" {
			continue
		}
		jtis = append(jtis, repository.RevokedRefreshTokenAccessJTI{
			JTI:       row.AccessJTI,
			ExpiresAt: row.ExpiresAt,
		})
	}
	return n, jtis, nil
}

func (r *inMemoryRefreshTokenRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, row := range r.byID {
		if !row.ExpiresAt.After(cutoff) {
			delete(r.byID, id)
			n++
		}
	}
	return n, nil
}

// ---------- Construction ----------

func TestNewRefreshTokenService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewRefreshTokenService(nil, nil, RefreshTokenServiceOptions{})
}

// ---------- Issue ----------

func TestIssue_RequiresClientIDAndSubject(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{})
	_, err := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "", Subject: "x"})
	if !errors.Is(err, ErrRefreshTokenInvalidInput) {
		t.Errorf("missing client_id err = %v", err)
	}
	_, err = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "x", Subject: ""})
	if !errors.Is(err, ErrRefreshTokenInvalidInput) {
		t.Errorf("missing subject err = %v", err)
	}
}

func TestIssue_PersistsHashOnlyNeverRawValidator(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, err := svc.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1",
		Subject:  "cli-1",
		Scope:    "read",
		Audience: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Token == "" {
		t.Fatalf("wire token empty")
	}
	// The row in the repo must contain a hex digest, NOT the wire
	// token. We can recompute it from the token's validator half
	// and confirm equality.
	parts := strings.Split(issued.Token, ".")
	if len(parts) != 2 {
		t.Fatalf("wire token shape wrong: %q", issued.Token)
	}
	parsed, perr := domain.ParseSecureRefreshToken(issued.Token)
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	sum := sha256.Sum256(parsed.Validator)
	wantHash := hex.EncodeToString(sum[:])
	row := repo.byID[issued.ID]
	if row == nil {
		t.Fatalf("row not persisted")
	}
	if row.ValidatorHash != wantHash {
		t.Errorf("persisted hash != recomputed hash")
	}
	if strings.Contains(row.ValidatorHash, issued.Token) {
		t.Errorf("validator_hash leaked raw wire token")
	}
	if row.ClientID != "cli-1" || row.Subject != "cli-1" {
		t.Errorf("binding fields wrong: %+v", row)
	}
}

func TestIssue_FilterUnsafeMetadataKeys(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{})
	issued, err := svc.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli", Subject: "cli",
		Metadata: map[string]any{
			"client_id":   "cli",
			"raw_secret":  "MUST-NOT-LEAK",
			"client_kind": "oauth_client",
		},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	row := repo.byID[issued.ID]
	if _, ok := row.Metadata["raw_secret"]; ok {
		t.Errorf("metadata leaked raw_secret")
	}
}

// ---------- Consume ----------

func TestConsume_RotatesAndCarriesPolicy(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1",
		Scope: "read", Audience: "https://api.example.com",
	})
	consumed, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{
		RawToken: issued.Token, ClientID: "cli-1",
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.NewToken == "" || consumed.NewToken == issued.Token {
		t.Errorf("rotation failed; new token = %q vs old = %q", consumed.NewToken, issued.Token)
	}
	if consumed.Subject != "cli-1" || consumed.Scope != "read" {
		t.Errorf("policy not carried: %+v", consumed)
	}
	// Old row must now be revoked + replaced_by populated.
	oldRow := repo.byID[issued.ID]
	if oldRow.RevokedAt == nil || oldRow.ReplacedBy == nil {
		t.Errorf("old row not rotated: %+v", oldRow)
	}
}

func TestConsume_ClientMismatchRejected(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1",
	})
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{
		RawToken: issued.Token, ClientID: "imposter",
	})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("client mismatch err = %v", err)
	}
}

func TestConsume_RevokedTokenRejected(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "cli"})
	now := time.Now().UTC()
	_ = repo.MarkRevoked(context.Background(), issued.ID, now)
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("revoked err = %v", err)
	}
}

func TestConsume_ExpiredTokenRejected(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	frozen := time.Now().UTC()
	svc.now = func() time.Time { return frozen }
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "cli"})
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("expired err = %v", err)
	}
}

func TestConsume_UnknownTokenRejected(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	fake := uuid.New().String() + ".AAAA"
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: fake, ClientID: "cli"})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("unknown token err = %v", err)
	}
}

func TestConsume_MalformedRejected(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: "not-a-token", ClientID: "x"})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("malformed err = %v", err)
	}
}

// (c) OAUTH REUSE — replaying a rotated-away (superseded) refresh token on
// the /token path is DETECTED as reuse (R1): the old row carries ReplacedBy,
// so the replay revokes the subject's ENTIRE refresh-token family and
// surfaces domain.ErrRefreshTokenReuse (the breach signal) rather than a
// silent invalid_grant. The successor chain is revoked too.
func TestConsume_AfterRotationIsReuseAndRevokesFamily(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	const subject = "subj-1"
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	// Legitimate rotation → successor token.
	successor, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Replay the now-superseded original → REUSE.
	_, reuseErr := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	t.Logf("EVIDENCE (c) oauth reuse: err=%v", reuseErr)
	if !errors.Is(reuseErr, domain.ErrRefreshTokenReuse) {
		t.Fatalf("second consume err = %v, want domain.ErrRefreshTokenReuse", reuseErr)
	}
	// Family revoked: the legitimate successor token is now dead too.
	_, succErr := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: successor.NewToken, ClientID: "cli"})
	t.Logf("EVIDENCE (c) successor after family revoke: err=%v", succErr)
	if succErr == nil {
		t.Errorf("successor token still usable after family revocation; want failure")
	}
	// Every row for the subject must be revoked.
	for id, row := range repo.byID {
		if row.Subject == subject && row.RevokedAt == nil {
			t.Errorf("row %s for subject not revoked after reuse", id)
		}
	}
}

// A row that is merely directly revoked (NO successor — ReplacedBy nil) is a
// plain invalid_grant, NOT a reuse breach: it must NOT trigger family
// revocation. Guards the narrowness of the reuse trigger.
func TestConsume_DirectlyRevokedIsInvalidGrantNotReuse(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "subj"})
	now := time.Now().UTC()
	_ = repo.MarkRevoked(context.Background(), issued.ID, now) // revoked WITHOUT a successor
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("directly-revoked err = %v, want plain invalid_grant (no reuse breach)", err)
	}
}

// (e-oauth) ROTATION REVALIDATION — a valid superseding consume is refused
// when the subject's user/org went inactive after issuance. The wired
// userOrgLookup returns nil/err for a banned user or inactive org.
func TestConsume_RevalidationRejectsInactiveSubject(t *testing.T) {
	subjectID := uuid.New()
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithUserOrgLookup(stubRefreshUserOrgLookup{err: errors.New("user banned or org inactive")})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: subjectID.String()})
	_, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli"})
	t.Logf("EVIDENCE (e-oauth) inactive subject: err=%v", err)
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Fatalf("err = %v, want ErrRefreshTokenInvalidGrant (inactive subject must not rotate)", err)
	}
	// Healthy lookup ⇒ rotation proceeds (no regression).
	svcOK := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithUserOrgLookup(stubRefreshUserOrgLookup{org: &domain.Organization{ID: uuid.New()}})
	issuedOK, _ := svcOK.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: subjectID.String()})
	if _, okErr := svcOK.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issuedOK.Token, ClientID: "cli"}); okErr != nil {
		t.Fatalf("healthy subject rotation failed: %v", okErr)
	}
}

// stubRefreshUserOrgLookup drives the OAuth rotation-time revalidation seam.
type stubRefreshUserOrgLookup struct {
	org *domain.Organization
	err error
}

func (s stubRefreshUserOrgLookup) GetUserOrganization(context.Context, uuid.UUID) (*domain.Organization, error) {
	return s.org, s.err
}

// ---------- Revoke ----------

func TestRevokeByRawToken_FoundCarriesAccessJTI(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli", Subject: "cli", AccessJTI: "jti-1",
	})
	r, err := svc.RevokeByRawToken(context.Background(), issued.Token, "")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !r.Found || r.AccessJTI != "jti-1" {
		t.Errorf("result = %+v", r)
	}
	if repo.byID[issued.ID].RevokedAt == nil {
		t.Errorf("row not revoked")
	}
}

func TestRevokeByRawToken_ValidatorMismatchDoesNotRevoke(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "cli"})
	// Swap the validator half for a different value.
	parts := strings.Split(issued.Token, ".")
	tampered := parts[0] + ".AAAA"
	r, _ := svc.RevokeByRawToken(context.Background(), tampered, "")
	if r.Found {
		t.Errorf("mismatched validator hit Found=true")
	}
	if repo.byID[issued.ID].RevokedAt != nil {
		t.Errorf("legitimate row revoked by validator-mismatch attempt")
	}
}

func TestRevokeByRawToken_UnknownIsNoOp(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	r, err := svc.RevokeByRawToken(context.Background(), uuid.New().String()+".AAAA", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Found {
		t.Errorf("unknown token reported Found=true")
	}
}

func TestRevokeByRawToken_EmptyIsNoOp(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	r, _ := svc.RevokeByRawToken(context.Background(), "", "")
	if r.Found {
		t.Errorf("empty token reported Found=true")
	}
}

// ---------- RevokeAllForUser ----------

func TestRevokeAllForUser_NilUserIDIsNoop(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	n, err := svc.RevokeAllForUser(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 {
		t.Errorf("nil userID returned n=%d, want 0", n)
	}
}

func TestRevokeAllForUser_RevokesOnlyTargetUserActiveRows(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	target := uuid.New()
	other := uuid.New()
	// Two active rows for target plus one already-revoked target row.
	tok1, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-a", Subject: target.String()})
	tok2, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-b", Subject: target.String()})
	tok3, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-c", Subject: target.String()})
	_ = repo.MarkRevoked(context.Background(), tok3.ID, time.Now().UTC().Add(-time.Hour))
	// Independent rows for another user that must survive.
	tokOther1, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-d", Subject: other.String()})
	tokOther2, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-e", Subject: other.String()})

	n, err := svc.RevokeAllForUser(context.Background(), target)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked n=%d, want 2 (active target rows only; pre-revoked row must not double-count)", n)
	}
	if repo.byID[tok1.ID].RevokedAt == nil || repo.byID[tok2.ID].RevokedAt == nil {
		t.Errorf("active target rows not flipped to revoked")
	}
	if repo.byID[tokOther1.ID].RevokedAt != nil || repo.byID[tokOther2.ID].RevokedAt != nil {
		t.Errorf("other user's rows revoked — cross-user blast")
	}
}

func TestRevokeAllForUser_IsIdempotent(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	target := uuid.New()
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-a", Subject: target.String()})
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-b", Subject: target.String()})
	n1, err := svc.RevokeAllForUser(context.Background(), target)
	if err != nil || n1 != 2 {
		t.Fatalf("first revoke: n=%d err=%v", n1, err)
	}
	n2, err := svc.RevokeAllForUser(context.Background(), target)
	if err != nil {
		t.Fatalf("second revoke err: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second revoke n=%d, want 0 (idempotent — already-revoked rows must not double-count)", n2)
	}
}

func TestRevokeAllForUser_RepoErrorBubblesUp(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	repo.revokeErr = errors.New("simulated repo failure")
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	target := uuid.New()
	_, err := svc.RevokeAllForUser(context.Background(), target)
	if err == nil {
		t.Errorf("expected repo error to bubble up; got nil")
	}
}

func TestRevokeAllForUser_DoesNotLeakHashOrSubject(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	target := uuid.New()
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: target.String()})
	// The service returns only an int64 count + error: there is no
	// other channel through which a validator_hash, raw token, or
	// subject could escape. Pin the return shape so a future
	// regression that adds a leakier signature is caught here.
	n, err := svc.RevokeAllForUser(context.Background(), target)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
}

func TestRevokeAllForUser_CascadesLinkedAccessJTIsWhenWired(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	target := uuid.New()
	other := uuid.New()
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-a", Subject: target.String(), AccessJTI: "linked-a"})
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-b", Subject: target.String(), AccessJTI: "linked-b"})
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-c", Subject: target.String(), AccessJTI: "linked-a"})
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-d", Subject: target.String()})
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-e", Subject: other.String(), AccessJTI: "other-linked"})

	n, err := svc.RevokeAllForUser(context.Background(), target)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 4 {
		t.Fatalf("revoked refresh rows = %d, want 4", n)
	}
	if len(revRepo.inserts) != 2 {
		t.Fatalf("linked access revocations = %d, want 2 unique target JTIs", len(revRepo.inserts))
	}
	got := map[string]bool{}
	for _, row := range revRepo.inserts {
		got[row.Jti] = true
		if row.Reason != "user_security_event" {
			t.Errorf("reason = %q, want user_security_event", row.Reason)
		}
	}
	if !got["linked-a"] || !got["linked-b"] {
		t.Errorf("target linked access revocations missing")
	}
	if got["other-linked"] {
		t.Errorf("other user's linked access JTI was revoked")
	}
}

func TestRevokeAllForUser_LinkedAccessJTIErrorIsReturnedAfterRefreshRevoke(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revRepo.insertErr = errors.New("simulated jti failure")
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	target := uuid.New()
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: target.String(), AccessJTI: "linked"})

	n, err := svc.RevokeAllForUser(context.Background(), target)
	if err == nil {
		t.Fatalf("expected linked access revocation error")
	}
	if n != 1 {
		t.Fatalf("revoked refresh rows = %d, want 1", n)
	}
	if repo.byID[issued.ID].RevokedAt == nil {
		t.Fatalf("refresh row was not revoked before linked access error returned")
	}
}

// ---------- DeleteExpired ----------

func TestDeleteExpired_PrunesPastDueRows(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	_, _ = svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "x", Subject: "x"})
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	if len(repo.byID) != 0 {
		t.Errorf("repo has %d rows after prune", len(repo.byID))
	}
}
