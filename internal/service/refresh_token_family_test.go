package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Teeth for the OSS refresh-reuse → family-lineage convergence
// (RFC 9700 §4.13.2). These prove the automated reuse response is now
// FAMILY-scoped (only the compromised lineage dies) instead of subject-wide,
// while legacy NULL-family rows keep the old subject-wide fallback.

// TestConsume_ReuseRevokesOnlyFamily_SiblingSurvives is the primary teeth: one
// subject has TWO independent login families. Replaying a superseded token
// from family A revokes family A's live tip but leaves family B fully usable.
//
// REVERT-PROOF: reverting the reuse branch to s.repo.RevokeAllBySubject makes
// family B's tip (tb1) die too, so the "family B still rotates" assertion
// fails — proving the change from subject-wide to family-scoped is
// load-bearing.
// RULE: P0-REFRESH-1
func TestConsume_ReuseRevokesOnlyFamily_SiblingSurvives(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	ctx := context.Background()
	const subject = "user-shared"

	// Family A: r0 -> ta1 -> ta2 (live tip).
	rA0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	cA1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family A rotate r0->ta1: %v", err)
	}
	cA2, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cA1.NewToken, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family A rotate ta1->ta2: %v", err)
	}

	// Family B: a SECOND independent login for the same subject -> rb0 -> tb1.
	rB0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	cB1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rB0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family B rotate rb0->tb1: %v", err)
	}

	// Sanity: the two families really are distinct lineages.
	if repo.byID[rA0.ID].FamilyID == repo.byID[rB0.ID].FamilyID {
		t.Fatalf("families A and B share a family_id; test cannot isolate scope")
	}

	// THEFT: replay the already-rotated ta1 -> reuse breach for family A.
	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cA1.NewToken, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("replay of ta1 err = %v, want domain.ErrRefreshTokenReuse", reuseErr)
	}

	// Family A's live tip ta2 is now revoked -> rotating it fails.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cA2.NewToken, ClientID: "cli"}); err == nil {
		t.Errorf("family A tip ta2 still usable after reuse; want revoked")
	}

	// TEETH: family B's tip tb1 is a DIFFERENT lineage and MUST survive.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cB1.NewToken, ClientID: "cli"}); err != nil {
		t.Errorf("family B tip tb1 rotate = %v, want success (sibling family must survive)", err)
	}
}

// TestConsume_NormalRotation_DoesNotRevokeFamily is the happy-path guard:
// ordinary one-time rotation (no replay of a superseded token) must NOT trip
// family revocation — the live tip stays usable.
func TestConsume_NormalRotation_DoesNotRevokeFamily(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	_ = repo
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	ctx := context.Background()

	r0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: "user-happy"})
	c1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: r0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("rotate r0->t1: %v", err)
	}
	c2, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: c1.NewToken, ClientID: "cli"})
	if err != nil {
		t.Fatalf("rotate t1->t2: %v", err)
	}
	// The live tip after normal rotation is still usable.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: c2.NewToken, ClientID: "cli"}); err != nil {
		t.Errorf("live tip t2 after normal rotation = %v, want success (family must NOT be revoked)", err)
	}
}

// TestConsume_LegacyNullFamily_ReuseFallsBackSubjectWide proves the migration
// fallback: a pre-migration row carries no family_id, so on reuse the service
// falls back to subject-wide revocation (the old strong behavior) — a
// concurrent DIFFERENT-lineage row for the same subject is also cut.
func TestConsume_LegacyNullFamily_ReuseFallsBackSubjectWide(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	ctx := context.Background()
	const subject = "user-legacy"

	// Legacy family A: issue then blank the family_id on BOTH the root and
	// its successor (simulating pre-migration NULL-family rows), rotate once.
	rA0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	repo.byID[rA0.ID].FamilyID = ""
	cA1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("legacy rotate r0->ta1: %v", err)
	}
	// The successor inherited "" (legacy), so it is also NULL-family.

	// A separate live family B for the same subject (also legacy for this
	// test, to show subject-wide fallback cuts everything).
	rB0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	repo.byID[rB0.ID].FamilyID = ""

	// Replay the superseded legacy root -> reuse; FamilyID=="" -> subject-wide.
	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("legacy reuse err = %v, want domain.ErrRefreshTokenReuse", reuseErr)
	}
	// Subject-wide fallback: EVERY active row for the subject is revoked,
	// including family B and the family-A successor.
	for id, row := range repo.byID {
		if row.Subject == subject && row.RevokedAt == nil {
			t.Errorf("row %s for subject not revoked under legacy subject-wide fallback", id)
		}
	}
	_ = cA1
}

// revokedJTIs returns the set of JTIs the fake denylist recorded.
func revokedJTIs(revRepo *fakeRevocationRepo) map[string]bool {
	out := map[string]bool{}
	for _, row := range revRepo.inserts {
		out[row.Jti] = true
	}
	return out
}

// TestConsume_Reuse_CascadesFamilyAccessJTI_SiblingUntouched is the teeth for
// the access-jti cascade: on reuse, the compromised FAMILY's live access
// token is denylisted immediately (not left alive to its TTL), while the
// sibling family's access token — a different lineage — is untouched.
//
// REVERT-PROOF: dropping the s.revokeLinkedAccessJTIs cascade (reverting
// revokeReuseLineage to the plain RevokeByFamily path) leaves jti-A-tip NOT
// denylisted, so the IsRevoked(jti-A-tip) assertion fails.
func TestConsume_Reuse_CascadesFamilyAccessJTI_SiblingUntouched(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	ctx := context.Background()
	const subject = "user-cascade"

	// Family A: rA0 -> ta1 -> ta2 (live tip). Stamp the tip's access jti,
	// as the token endpoint would via SetAccessJTI after minting.
	rA0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	cA1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family A r0->ta1: %v", err)
	}
	cA2, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cA1.NewToken, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family A ta1->ta2: %v", err)
	}
	if err := svc.SetAccessJTI(ctx, cA2.NewID, "jti-A-tip"); err != nil {
		t.Fatalf("SetAccessJTI A: %v", err)
	}

	// Family B: rB0 -> tb1 (live tip) with its own access jti.
	rB0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	cB1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rB0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("family B rb0->tb1: %v", err)
	}
	if err := svc.SetAccessJTI(ctx, cB1.NewID, "jti-B-tip"); err != nil {
		t.Fatalf("SetAccessJTI B: %v", err)
	}

	// THEFT: replay family A's superseded ta1 -> reuse.
	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cA1.NewToken, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("reuse err = %v, want domain.ErrRefreshTokenReuse", reuseErr)
	}

	// CASCADE: family A's live access token is denylisted immediately.
	if ok, _ := revSvc.IsRevoked(ctx, "jti-A-tip"); !ok {
		t.Errorf("family A tip access jti NOT denylisted after reuse; want immediate kill")
	}
	// SCOPE: family B's access token is a different lineage, untouched.
	if ok, _ := revSvc.IsRevoked(ctx, "jti-B-tip"); ok {
		t.Errorf("sibling family B access jti was denylisted; family scope violated")
	}
	if got := revokedJTIs(revRepo); got["jti-B-tip"] {
		t.Errorf("sibling family B jti recorded in denylist: %v", got)
	}
	// Refresh-row scoping still holds: family B's tip still rotates.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: cB1.NewToken, ClientID: "cli"}); err != nil {
		t.Errorf("family B tip tb1 rotate = %v, want success (sibling survives)", err)
	}
}

// TestConsume_Reuse_LegacyNullFamily_CascadesSubjectWide proves the legacy
// fallback also cascades: a NULL-family reuse denylists the subject's active
// rows' access jtis subject-wide.
func TestConsume_Reuse_LegacyNullFamily_CascadesSubjectWide(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	ctx := context.Background()
	const subject = "user-legacy-cascade"

	// Legacy family A: issue, blank family_id, rotate; stamp the successor's
	// access jti.
	rA0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: subject})
	repo.byID[rA0.ID].FamilyID = ""
	cA1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("legacy r0->ta1: %v", err)
	}
	if err := svc.SetAccessJTI(ctx, cA1.NewID, "jti-legacy-tip"); err != nil {
		t.Fatalf("SetAccessJTI legacy: %v", err)
	}

	// Replay the superseded legacy root -> reuse -> subject-wide cascade.
	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rA0.Token, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("legacy reuse err = %v, want domain.ErrRefreshTokenReuse", reuseErr)
	}
	if ok, _ := revSvc.IsRevoked(ctx, "jti-legacy-tip"); !ok {
		t.Errorf("legacy NULL-family reuse did NOT cascade subject-wide onto the access jti")
	}
}

// TestConsume_Reuse_CascadeStoreErrorIsFailSoft proves the fail-soft
// posture: a denylist-store error inside the cascade must NOT change the
// wire response — reuse still returns domain.ErrRefreshTokenReuse, and the
// compromised refresh family is still revoked.
func TestConsume_Reuse_CascadeStoreErrorIsFailSoft(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revRepo.insertErr = errors.New("denylist store down")
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	ctx := context.Background()

	r0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: "user-failsoft"})
	c1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: r0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("rotate r0->t1: %v", err)
	}
	_ = svc.SetAccessJTI(ctx, c1.NewID, "jti-failsoft")

	// Reuse: the cascade's RevokeJTI errors, but the wire response is
	// unchanged.
	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: r0.Token, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("reuse err = %v, want domain.ErrRefreshTokenReuse despite denylist-store error", reuseErr)
	}
	// The refresh family was still revoked (tip dead) even though the jti
	// cascade failed.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: c1.NewToken, ClientID: "cli"}); err == nil {
		t.Errorf("family tip still usable after reuse; refresh-row revocation should have run before the cascade")
	}
}

// TestConsume_Reuse_NoRevocationService_NoCascadeNoPanic proves the
// no-cascade fallback: with NO TokenRevocationService wired, reuse still
// revokes the refresh family and returns ErrRefreshTokenReuse without panic —
// there is simply no access-jti denylist step.
func TestConsume_Reuse_NoRevocationService_NoCascadeNoPanic(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	ctx := context.Background()

	r0, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: "user-no-rev"})
	c1, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: r0.Token, ClientID: "cli"})
	if err != nil {
		t.Fatalf("rotate r0->t1: %v", err)
	}
	_ = svc.SetAccessJTI(ctx, c1.NewID, "jti-orphan")

	_, reuseErr := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: r0.Token, ClientID: "cli"})
	if reuseErr != domain.ErrRefreshTokenReuse {
		t.Fatalf("reuse err = %v, want domain.ErrRefreshTokenReuse (no-revocation-service path)", reuseErr)
	}
	// The family's refresh rows are still revoked (t1 tip dead).
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: c1.NewToken, ClientID: "cli"}); err == nil {
		t.Errorf("family tip still usable after reuse with no revocation service")
	}
}

// TestConsume_WrongClient_RevokesFamilyAndCascades is the CE-SEC-4b teeth
// (RFC 9700 §4.13.2 client binding): a DIFFERENT client presenting another
// client's ACTIVE refresh token revokes the presented token's rotation family
// (its live refresh rows + linked access jtis) while returning the UNCHANGED
// generic invalid_grant, and a SEPARATE family survives (family-scoped, not
// global).
//
// Revert-proof: remove the s.revokeReuseLineage call in the wrong-client
// branch and family F stays active — the correct client re-presenting RT_F
// rotates successfully → this test fails.
func TestConsume_WrongClient_RevokesFamilyAndCascades(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	revSvc := NewTokenRevocationService(nil, revRepo)
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(revSvc)
	ctx := context.Background()
	const subject = "user-wrongclient"

	// Family F: client A, with a linked access jti.
	rF, err := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "client-A", Subject: subject})
	if err != nil {
		t.Fatalf("issue F: %v", err)
	}
	if err := svc.SetAccessJTI(ctx, rF.ID, "jti-F"); err != nil {
		t.Fatalf("SetAccessJTI F: %v", err)
	}
	// Family G: a SEPARATE client-A session (independent family) that must
	// survive the family-F kill.
	rG, err := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "client-A", Subject: subject})
	if err != nil {
		t.Fatalf("issue G: %v", err)
	}
	if repo.byID[rF.ID].FamilyID == repo.byID[rG.ID].FamilyID {
		t.Fatalf("families F and G share a family_id; cannot isolate scope")
	}

	// WRONG-CLIENT: client B presents A's ACTIVE refresh token RT_F.
	_, err = svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rF.Token, ClientID: "client-B"})
	// (b) wire byte-identical: still the generic invalid_grant, NOT the reuse
	// breach sentinel.
	if !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Fatalf("wrong-client err = %v, want ErrRefreshTokenInvalidGrant (wire unchanged)", err)
	}

	// (a) Family F is revoked: the RIGHT client A re-presenting RT_F now
	// fails (RevokeByFamily is active-scoped, so it revoked RT_F itself).
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rF.Token, ClientID: "client-A"}); err == nil {
		t.Errorf("RT_F still usable by the correct client after wrong-client presentation; want revoked")
	}
	// Linked access jti denylisted (revocation service + jti-extension wired).
	if ok, _ := revSvc.IsRevoked(ctx, "jti-F"); !ok {
		t.Errorf("family F access jti not denylisted after wrong-client presentation")
	}
	// Family G survives: client A rotates RT_G fine — the kill is family-
	// scoped, not global.
	if _, err := svc.Consume(ctx, ConsumeRefreshTokenInput{RawToken: rG.Token, ClientID: "client-A"}); err != nil {
		t.Errorf("family G rotate = %v, want success (family-scoped, not global)", err)
	}
}
