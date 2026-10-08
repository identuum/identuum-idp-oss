package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// F7 P15 (SEC-MFA-REVIEW-2026-10-08, owner ruling bb): the OAuth refresh
// grant renewed an app's tokens however the user had signed in, so an
// organization that later required MFA never reached them. The family now
// records the sign-in's acr; under a required policy a family without MFA
// (or with no record, issued before this change) is refused at its next use.
func TestIssueRefresh_RequiredMFAPolicyNeedsAnMFASignIn(t *testing.T) {
	org := uuid.New()
	required, optional := "required", "optional"
	cases := []struct {
		name   string
		policy *string
		acr    any // nil: no record on the family
		ok     bool
	}{
		{"required, password sign-in", &required, auth.ACRPassword, false},
		{"required, no record on the family", &required, nil, false},
		{"required, MFA sign-in", &required, auth.ACRMFA, true},
		{"required, phishing-resistant sign-in", &required, auth.ACRPhishingResistant, true},
		{"optional, password sign-in", &optional, auth.ACRPassword, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := &domain.User{ID: uuid.New(), OrganizationID: org, MFAPolicy: tc.policy}
			ed := genEdDSAKey(t, "kid-eddsa")
			rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
			svc := NewTokenService(nil, &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}, TokenServiceOptions{Issuer: audTestIssuer}).
				WithRefreshTokenService(rts).
				WithRefreshSubjectLookup(refreshSubjects{user.ID: user})
			in := IssueRefreshTokenInput{ClientID: "cli-1", Subject: user.ID.String()}
			if tc.acr != nil {
				in.Metadata = map[string]any{RefreshMetadataAuthACR: tc.acr}
			}
			issued, err := rts.Issue(context.Background(), in)
			if err != nil {
				t.Fatalf("seed: %v", err)
			}
			client := newConfidentialOAuthClient()
			client.OrganizationID = org
			_, err = svc.IssueRefresh(context.Background(), client, RefreshTokenRequest{GrantType: "refresh_token", RefreshToken: issued.Token})
			if tc.ok && err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrTokenServiceInvalidGrant) {
				t.Fatalf("refresh: %v; want ErrTokenServiceInvalidGrant", err)
			}
		})
	}
}
