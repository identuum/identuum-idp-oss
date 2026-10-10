package runtime

import (
	"context"
	"fmt"
	"io"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const advertiseRS256Env = "IDENTUUM_IDP_ADVERTISE_RS256"

// ensureAdvertisedRS256Key leaves the default-off path untouched. A fresh
// opted-in installation needs its normal signer as well as RSA: otherwise
// first-run setup could see only RSA and skip creating its EdDSA key.
//
// It runs before the single-replica lease decides which process serves, and
// the lease can be switched off, so the read below only skips key generation
// on an ordinary restart. A missing key is created through EnsureActive, which
// re-decides under a database lock: processes starting together create one.
func ensureAdvertisedRS256Key(ctx context.Context, keys *service.KeyService, enabled bool, stdout io.Writer) error {
	if !enabled {
		return nil
	}
	active, err := keys.ListActive(ctx)
	if err != nil {
		return err
	}
	var hasDefault, hasRSA bool
	for _, key := range active {
		if key.State != domain.KeyStateActive || key.PrivateKey == "" {
			continue
		}
		switch key.Algorithm {
		case domain.KeyAlgorithmEdDSA, domain.KeyAlgorithmES256:
			hasDefault = true
		case domain.KeyAlgorithmRS256:
			hasRSA = true
		}
	}
	if !hasDefault {
		if _, err := keys.EnsureActive(ctx, service.GenerateKeyOptions{Algorithm: "EdDSA"}, domain.KeyAlgorithmEdDSA, domain.KeyAlgorithmES256); err != nil {
			return err
		}
	}
	if !hasRSA {
		if _, err := keys.EnsureActive(ctx, service.GenerateKeyOptions{Algorithm: "RS256"}, domain.KeyAlgorithmRS256); err != nil {
			return err
		}
	}
	fmt.Fprintln(stdout, "identuum-idp: serve: RS256 is advertised; EdDSA remains the default signer (ES256 fallback)")
	return nil
}
