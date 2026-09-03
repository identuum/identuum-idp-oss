package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// acJTIRevokerFake records RevokeJTI calls.
type acJTIRevokerFake struct {
	mu      sync.Mutex
	revoked map[string]time.Time
	reasons map[string]string
	fail    error
}

func (f *acJTIRevokerFake) RevokeJTI(_ context.Context, jti string, expiresAt time.Time, reason string, _ map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.revoked == nil {
		f.revoked = map[string]time.Time{}
		f.reasons = map[string]string{}
	}
	f.revoked[jti] = expiresAt
	f.reasons[jti] = reason
	return nil
}

func TestIssueAgentCommunication_RecordsTheJTIBoundToTheAuthorization(t *testing.T) {
	w := newACIssuanceWorld(t)
	resp, rec, err := w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), w.request(t, w.keyA, w.aciA()))
	require.NoError(t, err)
	claims := decodeClaims(t, resp.AccessToken)
	require.Len(t, w.issued.rows, 1)
	row := w.issued.rows[0]
	assert.Equal(t, claims["jti"], row.JTI)
	assert.Equal(t, w.auth.ID, row.AuthorizationID)
	assert.Equal(t, rec.ACI, row.ACI)
	assert.Equal(t, rec.ExpiresAt, row.ExpiresAt)
	assert.Equal(t, w.now, row.IssuedAt)

	// A token that cannot be recorded is never handed out.
	w.issued.fail = errors.New("connection reset by peer")
	resp, rec, err = w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), w.request(t, w.keyA, w.aciA()))
	require.Error(t, err)
	assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	assert.Nil(t, resp)
	assert.Nil(t, rec)
}

func TestRevoke_PropagatesToLiveIssuedTokens(t *testing.T) {
	f := newACFixture(t)
	a, err := f.svc.Create(context.Background(), f.input())
	require.NoError(t, err)
	tokens := &acIssuedTokensFake{}
	revoker := &acJTIRevokerFake{}
	f.svc.WithRevocationPropagation(tokens, revoker)
	require.True(t, f.svc.HasRevocationPropagation())

	live1 := domain.AgentCommunicationToken{JTI: "jti-a", AuthorizationID: a.ID, ACI: a.Participants[0].ACI, ExpiresAt: f.now.Add(4 * time.Minute), IssuedAt: f.now}
	live2 := domain.AgentCommunicationToken{JTI: "jti-b", AuthorizationID: a.ID, ACI: a.Participants[1].ACI, ExpiresAt: f.now.Add(2 * time.Minute), IssuedAt: f.now}
	expired := domain.AgentCommunicationToken{JTI: "jti-old", AuthorizationID: a.ID, ACI: a.Participants[0].ACI, ExpiresAt: f.now.Add(-time.Minute), IssuedAt: f.now.Add(-6 * time.Minute)}
	other := domain.AgentCommunicationToken{JTI: "jti-other", AuthorizationID: uuid.New(), ACI: uuid.New(), ExpiresAt: f.now.Add(4 * time.Minute), IssuedAt: f.now}
	for _, tk := range []domain.AgentCommunicationToken{live1, live2, expired, other} {
		require.NoError(t, tokens.Insert(context.Background(), &tk))
	}

	revoked, err := f.svc.Revoke(context.Background(), f.org, a.ID, f.owner, "compromised")
	require.NoError(t, err)
	assert.NotNil(t, revoked.RevokedAt)
	assert.Len(t, revoker.revoked, 2, "both live tokens of BOTH participants are revoked")
	assert.Equal(t, live1.ExpiresAt, revoker.revoked["jti-a"])
	assert.Equal(t, live2.ExpiresAt, revoker.revoked["jti-b"])
	assert.Equal(t, AgentCommunicationTokenRevocationReason, revoker.reasons["jti-a"])
	_, expiredTouched := revoker.revoked["jti-old"]
	assert.False(t, expiredTouched, "an already-expired token needs no revocation row")
	_, otherTouched := revoker.revoked["jti-other"]
	assert.False(t, otherTouched, "another authorization's tokens are untouched")

	// The idempotent repeat propagates again (heals a partial earlier run).
	late := domain.AgentCommunicationToken{JTI: "jti-late", AuthorizationID: a.ID, ACI: a.Participants[0].ACI, ExpiresAt: f.now.Add(3 * time.Minute), IssuedAt: f.now}
	require.NoError(t, tokens.Insert(context.Background(), &late))
	_, err = f.svc.Revoke(context.Background(), f.org, a.ID, f.owner, "again")
	require.NoError(t, err)
	assert.Contains(t, revoker.revoked, "jti-late")
}

func TestRevoke_PropagationStoreErrorsAreUnavailability(t *testing.T) {
	ctx := context.Background()
	t.Run("issued-token store", func(t *testing.T) {
		f := newACFixture(t)
		a, err := f.svc.Create(ctx, f.input())
		require.NoError(t, err)
		tokens := &acIssuedTokensFake{fail: errors.New("dial tcp: connection refused")}
		f.svc.WithRevocationPropagation(tokens, &acJTIRevokerFake{})
		_, err = f.svc.Revoke(ctx, f.org, a.ID, f.owner, "x")
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
		stored, gerr := f.svc.Get(ctx, f.org, a.ID)
		require.NoError(t, gerr)
		assert.NotNil(t, stored.RevokedAt, "the authorization row IS revoked; only the propagation is unanswered")
	})
	t.Run("revocation store", func(t *testing.T) {
		f := newACFixture(t)
		a, err := f.svc.Create(ctx, f.input())
		require.NoError(t, err)
		tokens := &acIssuedTokensFake{}
		require.NoError(t, tokens.Insert(ctx, &domain.AgentCommunicationToken{JTI: "j", AuthorizationID: a.ID, ACI: a.Participants[0].ACI, ExpiresAt: f.now.Add(time.Minute), IssuedAt: f.now}))
		f.svc.WithRevocationPropagation(tokens, &acJTIRevokerFake{fail: errors.New("pq: shutting down")})
		_, err = f.svc.Revoke(ctx, f.org, a.ID, f.owner, "x")
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
	t.Run("without propagation wired the stamp alone succeeds", func(t *testing.T) {
		f := newACFixture(t)
		a, err := f.svc.Create(ctx, f.input())
		require.NoError(t, err)
		assert.False(t, f.svc.HasRevocationPropagation())
		revoked, err := f.svc.Revoke(ctx, f.org, a.ID, f.owner, "x")
		require.NoError(t, err)
		assert.NotNil(t, revoked.RevokedAt)
	})
}
