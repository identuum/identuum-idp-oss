package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakeClientLiveness struct {
	client *domain.Client
	err    error
}

func (f *fakeClientLiveness) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return f.client, f.err
}

// OSS-CLIENTS: a token whose client is gone is inactive at userinfo and
// introspection; a lookup error fails closed as a store outage; a token with
// no client_id (a login session token) is not looked up.
func TestIntrospect_ClientLiveness(t *testing.T) {
	uid := uuid.New()
	clientBound := &IntrospectionClaims{Sub: uid.String(), UserID: uid, ClientID: "client-1", Jti: "jti-1"}
	sessionBound := &IntrospectionClaims{Sub: uid.String(), UserID: uid, Jti: "jti-2"}
	cases := []struct {
		name       string
		claims     *IntrospectionClaims
		lookup     *fakeClientLiveness
		wantActive bool
		wantStore  bool
	}{
		{"client deleted", clientBound, &fakeClientLiveness{err: domain.ErrClientNotFound}, false, false},
		{"client nil", clientBound, &fakeClientLiveness{}, false, false},
		{"lookup error fails closed", clientBound, &fakeClientLiveness{err: errors.New("db down")}, false, true},
		{"client live", clientBound, &fakeClientLiveness{client: &domain.Client{ClientID: "client-1"}}, true, false},
		{"no client_id is not looked up", sessionBound, &fakeClientLiveness{err: errors.New("must not be called")}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewIntrospectionService(nil, &fakeIntrospector{claims: tc.claims}, nil).WithClientLiveness(tc.lookup)
			resp, err := svc.IntrospectVerdict(context.Background(), "ANY")
			if resp.Active != tc.wantActive || domain.IsAuthStoreUnavailable(err) != tc.wantStore {
				t.Errorf("IntrospectVerdict = active %v, store-unavailable %v; want %v, %v", resp.Active, domain.IsAuthStoreUnavailable(err), tc.wantActive, tc.wantStore)
			}
			_, active, err := svc.IntrospectActiveClaimsVerdict(context.Background(), "ANY")
			if active != tc.wantActive || domain.IsAuthStoreUnavailable(err) != tc.wantStore {
				t.Errorf("IntrospectActiveClaimsVerdict = active %v, store-unavailable %v; want %v, %v", active, domain.IsAuthStoreUnavailable(err), tc.wantActive, tc.wantStore)
			}
		})
	}
}
