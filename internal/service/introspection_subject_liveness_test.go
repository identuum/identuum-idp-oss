package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// A token bound to a session is active only while that session, its user and
// its organization are. Introspection applies the verdict the bearer middleware
// and userinfo apply, instead of reporting a signed, unexpired token active
// after its session was revoked or its user banned.

type stubSubjects struct {
	live  bool
	err   error
	calls int
	last  oidc.PrincipalRef
}

func (s *stubSubjects) ResolveSubject(_ context.Context, ref oidc.PrincipalRef) (bool, error) {
	s.calls++
	s.last = ref
	return s.live, s.err
}

func TestIntrospect_SessionBoundTokenIsActiveOnlyWhileTheSubjectIsLive(t *testing.T) {
	uid, sid := uuid.New(), uuid.New()
	sessionBound := &IntrospectionClaims{Sub: uid.String(), UserID: uid, SessionID: sid, Jti: "jti-1"}
	machine := &IntrospectionClaims{Sub: "cli-1", ClientID: "cli-1", Jti: "jti-2"} // no session

	cases := []struct {
		name       string
		claims     *IntrospectionClaims
		subjects   *stubSubjects
		wantActive bool
		wantStore  bool
		wantCalls  int
	}{
		{"live session", sessionBound, &stubSubjects{live: true}, true, false, 1},
		{"revoked session or banned user", sessionBound, &stubSubjects{live: false}, false, false, 1},
		{"the check cannot run: fails closed as a store error", sessionBound, &stubSubjects{err: errors.New("db down")}, false, true, 1},
		{"a token with no session is not judged here", machine, &stubSubjects{live: false}, true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewIntrospectionService(nil, &fakeIntrospector{claims: tc.claims}, nil).WithSubjectResolver(tc.subjects)
			resp, err := svc.IntrospectVerdict(context.Background(), "ANY")
			if resp.Active != tc.wantActive || domain.IsAuthStoreUnavailable(err) != tc.wantStore {
				t.Errorf("IntrospectVerdict = active %v, store-unavailable %v; want %v, %v", resp.Active, domain.IsAuthStoreUnavailable(err), tc.wantActive, tc.wantStore)
			}
			if tc.subjects.calls != tc.wantCalls {
				t.Errorf("resolver consulted %d times, want %d", tc.subjects.calls, tc.wantCalls)
			}
			if tc.wantCalls > 0 && tc.subjects.last.SessionID != sid.String() {
				t.Errorf("resolver asked about session %q, want %q", tc.subjects.last.SessionID, sid.String())
			}
		})
	}

	t.Run("no resolver wired: as before", func(t *testing.T) {
		svc := NewIntrospectionService(nil, &fakeIntrospector{claims: sessionBound}, nil)
		if resp, err := svc.IntrospectVerdict(context.Background(), "ANY"); err != nil || !resp.Active {
			t.Errorf("IntrospectVerdict without a resolver = %v, %v; want active", resp.Active, err)
		}
	})
}
