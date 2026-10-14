package main

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// lateKeyRepo stands in for a store where another run inserted the first key
// between bootstrap's read and its locked re-check.
type lateKeyRepo struct {
	*memKeyRepo
}

func (r lateKeyRepo) CreateSigningKeyUnlessActive(ctx context.Context, key *domain.SigningKey, satisfiedBy []domain.KeyAlgorithm) (bool, error) {
	r.keys = append(r.keys, domain.SigningKey{
		KID: "other-run", Algorithm: domain.KeyAlgorithmES256, State: domain.KeyStateActive, PrivateKey: "x",
	})
	return r.memKeyRepo.CreateSigningKeyUnlessActive(ctx, key, satisfiedBy)
}

// A bootstrap that loses the race to another run's key creates none and says
// the key is already present, naming the key it found.
func TestBootstrapCore_LostKeyRaceReusesTheOtherRunsKey(t *testing.T) {
	t.Parallel()

	keys := &memKeyRepo{}
	deps := bootstrapDeps{Keys: lateKeyRepo{keys}, Users: &memUserRepo{}}
	var stdout, stderr bytes.Buffer
	if rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr); rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}
	if n := len(keys.keys); n != 1 || keys.keys[0].KID != "other-run" {
		t.Fatalf("bootstrap must reuse the other run's key; got %d keys", n)
	}
	out := stdout.String()
	if !strings.Contains(out, "signing key already present (kid=other-run, alg=ES256)") || strings.Contains(out, "created signing key") {
		t.Fatalf("expected the 'already present' line naming the other run's key; got %q", out)
	}
}

func TestBootstrapKeySatisfiedBy(t *testing.T) {
	t.Parallel()

	defaults := []domain.KeyAlgorithm{domain.KeyAlgorithmEdDSA, domain.KeyAlgorithmES256}
	for _, tc := range []struct {
		alg  domain.KeyAlgorithm
		want []domain.KeyAlgorithm
	}{
		{domain.KeyAlgorithmEdDSA, defaults},
		{domain.KeyAlgorithmES256, defaults},
		{domain.KeyAlgorithmRS256, []domain.KeyAlgorithm{domain.KeyAlgorithmRS256}},
	} {
		if got := bootstrapKeySatisfiedBy(tc.alg); !slices.Equal(got, tc.want) {
			t.Errorf("bootstrapKeySatisfiedBy(%s) = %v; want %v", tc.alg, got, tc.want)
		}
	}
}
