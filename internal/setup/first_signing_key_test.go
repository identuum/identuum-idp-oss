package setup

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// failingEnsureKeyRepo refuses the locked key insert while fail is set.
type failingEnsureKeyRepo struct {
	*memKeyRepo
	fail bool
}

func (r *failingEnsureKeyRepo) CreateSigningKeyUnlessActive(ctx context.Context, key *domain.SigningKey, satisfiedBy []domain.KeyAlgorithm) (bool, error) {
	if r.fail {
		return false, errors.New("test fake: store unavailable")
	}
	return r.memKeyRepo.CreateSigningKeyUnlessActive(ctx, key, satisfiedBy)
}

// A key store error refuses setup with a plain line and leaves setup open:
// the same setup token completes it once the store answers again, with one key.
func TestComplete_KeyStoreErrorRefusesAndKeepsSetupOpen(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	banner, err := h.svc.Initialize(ctx, h.dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	keys := &failingEnsureKeyRepo{memKeyRepo: h.keyRepo, fail: true}
	deps := h.svc.deps
	deps.KeyService = service.NewKeyService(keys)
	svc := New(deps)

	_, err = svc.Complete(ctx, h.dataDir, validCompleteInput(banner.SetupToken))
	if err == nil {
		t.Fatal("Complete succeeded although the key store refused the insert")
	}
	if !strings.HasPrefix(err.Error(), "setup complete: ") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("the refusal must be one plain line starting %q; got %q", "setup complete: ", err.Error())
	}
	if state, _ := h.repo.Get(ctx); state.IsComplete() {
		t.Fatal("a key store error must not mark setup complete")
	}
	if err := svc.VerifyToken(ctx, banner.SetupToken); err != nil {
		t.Fatalf("a key store error must leave the setup token usable; got %v", err)
	}

	keys.fail = false
	if _, err := svc.Complete(ctx, h.dataDir, validCompleteInput(banner.SetupToken)); err != nil {
		t.Fatalf("Complete after the store recovered: %v", err)
	}
	if n := len(h.keyRepo.keys); n != 1 {
		t.Fatalf("want exactly one signing key after the retry; got %d", n)
	}
}

// An existing active key is reused: setup adds none.
func TestComplete_ReusesAnExistingActiveKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.keyRepo.keys = append(h.keyRepo.keys, domain.SigningKey{
		KID: "existing", Algorithm: domain.KeyAlgorithmEdDSA, State: domain.KeyStateActive, PrivateKey: "x",
	})
	banner, err := h.svc.Initialize(ctx, h.dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := h.svc.Complete(ctx, h.dataDir, validCompleteInput(banner.SetupToken)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if n := len(h.keyRepo.keys); n != 1 || h.keyRepo.keys[0].KID != "existing" {
		t.Fatalf("setup must reuse the existing active key; got %d keys", n)
	}
}
