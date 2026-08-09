package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryAuthCodeRepo is a tiny OAuthAuthorizationCodeRepository.
type inMemoryAuthCodeRepo struct {
	byID       map[uuid.UUID]*domain.OAuthAuthorizationCode
	byCodeHash map[string]*domain.OAuthAuthorizationCode
}

func newAuthCodeRepo() *inMemoryAuthCodeRepo {
	return &inMemoryAuthCodeRepo{
		byID:       map[uuid.UUID]*domain.OAuthAuthorizationCode{},
		byCodeHash: map[string]*domain.OAuthAuthorizationCode{},
	}
}

func (r *inMemoryAuthCodeRepo) Insert(_ context.Context, c *domain.OAuthAuthorizationCode) error {
	cp := *c
	r.byID[c.ID] = &cp
	r.byCodeHash[c.CodeHash] = &cp
	return nil
}

// GetByCodeHashAnyState mirrors the production lookup: no consumed_at and no
// expires_at predicate, so a consumed code is still FOUND here. That asymmetry
// with GetActiveByCodeHash is the whole point of P0-1b — the fake must keep it.
func (r *inMemoryAuthCodeRepo) GetByCodeHashAnyState(_ context.Context, hash string) (*domain.OAuthAuthorizationCode, error) {
	c, ok := r.byCodeHash[hash]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *inMemoryAuthCodeRepo) GetActiveByCodeHash(_ context.Context, hash string, now time.Time) (*domain.OAuthAuthorizationCode, error) {
	c, ok := r.byCodeHash[hash]
	if !ok {
		return nil, nil
	}
	if c.ConsumedAt != nil {
		return nil, nil
	}
	if !c.ExpiresAt.After(now) {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *inMemoryAuthCodeRepo) MarkConsumed(_ context.Context, id uuid.UUID, at time.Time) (bool, error) {
	c, ok := r.byID[id]
	if !ok {
		return false, nil
	}
	if c.ConsumedAt != nil {
		return false, nil
	}
	c.ConsumedAt = &at
	return true, nil
}

func (r *inMemoryAuthCodeRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	var n int64
	for id, c := range r.byID {
		if !c.ExpiresAt.After(cutoff) {
			delete(r.byID, id)
			delete(r.byCodeHash, c.CodeHash)
			n++
		}
	}
	return n, nil
}

func pkceVerifierAndChallenge(t *testing.T) (string, string) {
	t.Helper()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func newAuthCodeHarness(t *testing.T) (*AuthorizationCodeService, *inMemoryAuthCodeRepo) {
	t.Helper()
	repo := newAuthCodeRepo()
	svc := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	return svc, repo
}

func baseCreateInput(challenge string) CreateAuthorizationCodeInput {
	return CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid profile",
		Audience:            "https://api.example.com",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
}

// ---------- Construction ----------

func TestNewAuthorizationCodeService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewAuthorizationCodeService(nil, nil, AuthorizationCodeServiceOptions{})
}

// ---------- Create ----------

func TestCreate_StoresHashOnlyNeverRawCode(t *testing.T) {
	svc, repo := newAuthCodeHarness(t)
	_, challenge := pkceVerifierAndChallenge(t)
	out, err := svc.Create(context.Background(), baseCreateInput(challenge))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.Code == "" {
		t.Fatalf("raw code empty")
	}
	sum := sha256.Sum256([]byte(out.Code))
	wantHash := hex.EncodeToString(sum[:])
	row := repo.byID[out.ID]
	if row.CodeHash != wantHash {
		t.Errorf("stored hash mismatch")
	}
	if strings.Contains(row.CodeHash, out.Code) {
		t.Errorf("stored hash contains raw code text")
	}
}

func TestCreate_MissingFieldsRejected(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	_, challenge := pkceVerifierAndChallenge(t)
	bad := baseCreateInput(challenge)
	bad.ClientID = ""
	if _, err := svc.Create(context.Background(), bad); !errors.Is(err, ErrAuthCodeInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestCreate_PlainMethodRejected(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	in := baseCreateInput("anything")
	in.CodeChallengeMethod = "plain"
	if _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrAuthCodeUnsupportedChallenge) {
		t.Errorf("err = %v", err)
	}
}

// ---------- Consume ----------

func TestConsume_ValidPKCESucceeds(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	verifier, challenge := pkceVerifierAndChallenge(t)
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	consumed, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.Scope != "openid profile" {
		t.Errorf("scope = %q", consumed.Scope)
	}
}

func TestConsume_SecondAttemptIsInvalidGrant(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	verifier, challenge := pkceVerifierAndChallenge(t)
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	if _, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestConsume_ExpiredIsInvalidGrant(t *testing.T) {
	repo := newAuthCodeRepo()
	svc := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	verifier, challenge := pkceVerifierAndChallenge(t)
	frozen := time.Now().UTC()
	svc.now = func() time.Time { return frozen }
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestConsume_WrongClientIsInvalidGrant(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	verifier, challenge := pkceVerifierAndChallenge(t)
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-other",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestConsume_WrongRedirectURIIsInvalidGrant(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	verifier, challenge := pkceVerifierAndChallenge(t)
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://imposter.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestConsume_WrongVerifierIsInvalidGrant(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	_, challenge := pkceVerifierAndChallenge(t)
	created, _ := svc.Create(context.Background(), baseCreateInput(challenge))
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: "wrong-verifier",
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

func TestConsume_UnknownCodeIsInvalidGrant(t *testing.T) {
	svc, _ := newAuthCodeHarness(t)
	verifier, _ := pkceVerifierAndChallenge(t)
	_, err := svc.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code:         "definitely-not-a-real-code",
		ClientID:     "cli-1",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("err = %v", err)
	}
}

// ---------- DeleteExpired ----------

func TestAuthCode_DeleteExpiredPrunesPastDueRows(t *testing.T) {
	repo := newAuthCodeRepo()
	svc := NewAuthorizationCodeService(nil, repo, AuthorizationCodeServiceOptions{TTL: time.Hour})
	_, challenge := pkceVerifierAndChallenge(t)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	_, _ = svc.Create(context.Background(), baseCreateInput(challenge))
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d", n)
	}
}
