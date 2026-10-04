package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// D-027 at the refresh grant: a user signs in only to apps of their own
// organization, and a refresh continues that sign-in. A refresh token issued
// before the rule to another organization's app stops at its next use; an app
// with no organization stays available to every organization.

type refreshSubjects map[uuid.UUID]*domain.User

func (m refreshSubjects) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := m[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func TestIssueRefresh_TheSubjectMustBeOfTheAppsOrganization(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	inA, inB := &domain.User{ID: uuid.New(), OrganizationID: orgA}, &domain.User{ID: uuid.New(), OrganizationID: orgB}
	users := refreshSubjects{inA.ID: inA, inB.ID: inB}

	refresh := func(t *testing.T, appOrg uuid.UUID, subject uuid.UUID) error {
		t.Helper()
		ed := genEdDSAKey(t, "kid-eddsa")
		rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
		svc := NewTokenService(nil, &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}, TokenServiceOptions{Issuer: audTestIssuer}).
			WithRefreshTokenService(rts).
			WithRefreshSubjectLookup(users)
		issued, err := rts.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-1", Subject: subject.String()})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		client := newConfidentialOAuthClient()
		client.OrganizationID = appOrg
		_, err = svc.IssueRefresh(context.Background(), client, RefreshTokenRequest{GrantType: "refresh_token", RefreshToken: issued.Token})
		return err
	}

	if err := refresh(t, orgA, inB.ID); !errors.Is(err, ErrTokenServiceInvalidGrant) {
		t.Errorf("an app of organization A refreshing for a user of B: err=%v, want ErrTokenServiceInvalidGrant", err)
	}
	if err := refresh(t, orgA, inA.ID); err != nil {
		t.Errorf("an app refreshing for a user of its own organization: %v", err)
	}
	if err := refresh(t, uuid.Nil, inB.ID); err != nil {
		t.Errorf("an app of no organization refreshing for any user: %v", err)
	}
	if err := refresh(t, orgA, uuid.New()); !errors.Is(err, ErrTokenServiceInvalidGrant) {
		t.Errorf("a refresh for a user that no longer exists: err=%v, want ErrTokenServiceInvalidGrant", err)
	}
}
