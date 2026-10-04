package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A refresh family does not slide forever. Every rotation hands the successor a
// fresh TTL, so a stolen refresh token that is kept in use never expires on its
// own; the family's age, read from its UUIDv7 id, caps that.

// rotateAt moves the service clock to base+age and rotates the token.
func rotateAt(t *testing.T, svc *RefreshTokenService, base time.Time, age time.Duration, raw string) (*ConsumeResult, error) {
	t.Helper()
	svc.now = func() time.Time { return base.Add(age) }
	return svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: raw, ClientID: "cli"})
}

func TestConsume_FamilyPastItsAbsoluteLifetimeIsRefused(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	// A sliding TTL far longer than the absolute lifetime: the row itself is
	// still unexpired, only the family's age can refuse it.
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: 400 * 24 * time.Hour})
	base := time.Now().UTC()
	svc.now = func() time.Time { return base }
	issued, err := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "user-old-family"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	day := 24 * time.Hour
	first, err := rotateAt(t, svc, base, 60*day, issued.Token)
	if err != nil {
		t.Fatalf("rotation inside the lifetime = %v, want success", err)
	}
	// The successor carries a fresh TTL, so without a cap it keeps sliding.
	if _, err := rotateAt(t, svc, base, 120*day, first.NewToken); !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("rotation of a family 120 days old = %v, want invalid_grant", err)
	}
}

func TestConsume_AbsoluteLifetimeKeepsLegacyAndForeignFamilies(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: 400 * 24 * time.Hour})
	base := time.Now().UTC()
	svc.now = func() time.Time { return base }
	day := 24 * time.Hour

	// A pre-migration row has no family id: its age is unknown, the cap does not apply.
	legacy, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "user-legacy"})
	repo.byID[legacy.ID].FamilyID = ""
	if _, err := rotateAt(t, svc, base, 200*day, legacy.Token); err != nil {
		t.Errorf("legacy row without a family id = %v, want success", err)
	}

	// A family id that is not a UUIDv7 carries no timestamp: same.
	foreign, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "user-v4"})
	repo.byID[foreign.ID].FamilyID = uuid.NewString()
	if _, err := rotateAt(t, svc, base, 200*day, foreign.Token); err != nil {
		t.Errorf("row with a non-v7 family id = %v, want success", err)
	}
}

func TestConsume_AbsoluteLifetimeIsConfigurable(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: 400 * 24 * time.Hour, AbsoluteLifetime: 10 * 24 * time.Hour})
	base := time.Now().UTC()
	svc.now = func() time.Time { return base }
	issued, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "user-short"})
	day := 24 * time.Hour

	if _, err := rotateAt(t, svc, base, 9*day, issued.Token); err != nil {
		t.Fatalf("rotation at 9 days with a 10-day lifetime = %v, want success", err)
	}
	other, _ := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli", Subject: "user-short-2"})
	if _, err := rotateAt(t, svc, base, 11*day, other.Token); !errors.Is(err, ErrRefreshTokenInvalidGrant) {
		t.Errorf("rotation at 11 days with a 10-day lifetime = %v, want invalid_grant", err)
	}
}

func TestFamilyStartedAt_ReadsTheUUIDv7Timestamp(t *testing.T) {
	want := time.Date(2026, 3, 1, 12, 30, 45, 123_000_000, time.UTC)
	id := uuid.UUID{}
	ms := want.UnixMilli()
	for i := 0; i < 6; i++ {
		id[i] = byte(ms >> (8 * (5 - i)))
	}
	id[6] = 0x70 | (id[6] & 0x0f)
	id[8] = 0x80 | (id[8] & 0x3f)

	got, ok := familyStartedAt(id.String())
	if !ok || !got.Equal(want) {
		t.Errorf("familyStartedAt(v7) = %v, %v; want %v, true", got, ok, want)
	}
	for _, bad := range []string{"", "not-a-uuid", uuid.NewString()} {
		if _, ok := familyStartedAt(bad); ok {
			t.Errorf("familyStartedAt(%q) ok = true, want false", bad)
		}
	}
}
