package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AudienceClientLookup resolves an application by its client id.
type AudienceClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// ReservedAudienceChecker returns the check APIResourceService uses to refuse
// an audience that is the issuer or an existing application's client id (H7).
// The issuer comparison ignores a trailing slash and letter case; a client
// lookup failure is returned so the caller refuses rather than passes. A nil
// clients lookup leaves only the issuer reserved.
func ReservedAudienceChecker(issuer string, clients AudienceClientLookup) func(ctx context.Context, audience string) (bool, error) {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "/")) }
	issuerNorm := norm(issuer)
	return func(ctx context.Context, audience string) (bool, error) {
		if issuerNorm != "" && norm(audience) == issuerNorm {
			return true, nil
		}
		if clients == nil {
			return false, nil
		}
		client, err := clients.GetClientByClientID(ctx, strings.TrimSpace(audience))
		switch {
		case errors.Is(err, domain.ErrClientNotFound):
			return false, nil
		case err != nil:
			return false, fmt.Errorf("service: reserved audience client lookup: %w", err)
		}
		return client != nil, nil
	}
}
