package handlers

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// clientReadWriter is the part of a test client store that
// mutateClientByReadAndWrite needs.
type clientReadWriter interface {
	GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	Update(ctx context.Context, c *domain.Client) error
}

// mutateClientByReadAndWrite is repository.ClientRepository.MutateClient for
// in-memory test stores: the same contract (a copy to fn, fn's error
// unchanged, not-found, every other read or write failure store-unavailable),
// without a lock, because these stores serve one request at a time. It reads
// and writes through r's own methods, so a store that counts or fails reads
// and writes keeps doing so.
func mutateClientByReadAndWrite(ctx context.Context, r clientReadWriter, id uuid.UUID, fn func(*domain.Client) error) (*domain.Client, *domain.Client, error) {
	cur, err := r.GetClientByID(ctx, id)
	if errors.Is(err, domain.ErrClientNotFound) || (err == nil && cur == nil) {
		return nil, nil, domain.ErrClientNotFound
	}
	if err != nil {
		return nil, nil, domain.AuthStoreUnavailable("client", err)
	}
	prior, result := *cur, *cur
	if err := fn(&result); err != nil {
		return nil, nil, err
	}
	if err := r.Update(ctx, &result); err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return nil, nil, err
		}
		return nil, nil, domain.AuthStoreUnavailable("client", err)
	}
	return &prior, &result, nil
}
