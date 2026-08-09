// Package service — BackchannelDeliveryAdminService is the
// site-admin façade over the `backchannel_logout_deliveries`
// table. It exposes:
//
//   - List      — paginated rows with optional status / client_id
//     filters.
//   - Get       — fetch by primary key.
//   - Replay    — mint a fresh logout_token (NEVER stored) and
//     re-attempt delivery via the existing
//     BackchannelLogoutService.
//
// Authorization gating lives at the HTTP layer
// (mw.RequireSiteAdmin); this service trusts that gate.
package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// BackchannelDeliveryAdminClientLookup is the seam used to resolve
// the row's client_id → *domain.Client at replay time. The
// existing ClientService satisfies it via GetClientByClientID.
type BackchannelDeliveryAdminClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// BackchannelDeliveryAdminService is the admin façade.
type BackchannelDeliveryAdminService struct {
	repo     repository.BackchannelLogoutDeliveryRepository
	delivery *BackchannelLogoutService
	clients  BackchannelDeliveryAdminClientLookup
}

// NewBackchannelDeliveryAdminService constructs the service.
//
//   - repo + delivery are REQUIRED.
//   - clients is OPTIONAL; without it, Replay returns
//     ErrBackchannelAdminClientLookupMissing because we cannot
//     mint a fresh logout_token without a resolved client.
func NewBackchannelDeliveryAdminService(report *lifecycle.StartupReport,
	repo repository.BackchannelLogoutDeliveryRepository,
	delivery *BackchannelLogoutService,
	clients BackchannelDeliveryAdminClientLookup,
) *BackchannelDeliveryAdminService {
	if repo == nil {
		report.Fatal("NewBackchannelDeliveryAdminService", "service: NewBackchannelDeliveryAdminService requires a non-nil repository")
	}
	if delivery == nil {
		report.Fatal("NewBackchannelDeliveryAdminService", "service: NewBackchannelDeliveryAdminService requires a non-nil BackchannelLogoutService")
	}
	return &BackchannelDeliveryAdminService{repo: repo, delivery: delivery, clients: clients}
}

// Sentinels.
var (
	ErrBackchannelAdminNotFound            = errors.New("service: backchannel delivery not found")
	ErrBackchannelAdminClientLookupMissing = errors.New("service: backchannel delivery admin requires a client lookup")
	ErrBackchannelAdminClientGone          = errors.New("service: client referenced by delivery no longer exists or has no backchannel_logout_uri")
)

// ListBackchannelDeliveriesInput drives List.
type ListBackchannelDeliveriesInput struct {
	Status   string
	ClientID string
	Limit    int
}

// List returns rows matching the filter. Limit defaults to 50 and
// is hard-capped at 200 inside the pgx layer.
func (s *BackchannelDeliveryAdminService) List(ctx context.Context, in ListBackchannelDeliveriesInput) ([]*domain.BackchannelLogoutDelivery, error) {
	return s.repo.List(ctx, repository.BackchannelLogoutDeliveryListFilter{
		Status:   in.Status,
		ClientID: in.ClientID,
		Limit:    in.Limit,
	})
}

// Get returns one row by id.
func (s *BackchannelDeliveryAdminService) Get(ctx context.Context, id uuid.UUID) (*domain.BackchannelLogoutDelivery, error) {
	row, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrBackchannelAdminNotFound
	}
	return row, nil
}

// ReplayResult is the projection returned to the operator. It
// echoes the new delivery row's id so the caller can poll the row
// for the outcome.
type ReplayResult struct {
	NewDeliveryID uuid.UUID
	HTTPStatus    int
	Delivered     bool
}

// Replay loads the original delivery row, resolves the referenced
// client, mints a FRESH logout_token (the original token bytes are
// never stored or replayed verbatim), and re-attempts delivery via
// BackchannelLogoutService.Deliver.
//
// Errors:
//   - ErrBackchannelAdminNotFound       — id not found.
//   - ErrBackchannelAdminClientGone     — client no longer exists
//     or has no
//     backchannel_logout_uri.
//   - ErrBackchannelAdminClientLookupMissing — service constructed
//     without a client
//     lookup.
func (s *BackchannelDeliveryAdminService) Replay(ctx context.Context, id uuid.UUID) (*ReplayResult, error) {
	row, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.clients == nil {
		return nil, ErrBackchannelAdminClientLookupMissing
	}
	client, err := s.clients.GetClientByClientID(ctx, row.ClientID)
	if err != nil || client == nil || client.BackchannelLogoutURI == "" {
		return nil, ErrBackchannelAdminClientGone
	}

	var subject, sessionID uuid.UUID
	if row.UserID != nil {
		subject = *row.UserID
	}
	if row.SessionID != nil {
		sessionID = *row.SessionID
	}

	result, delivErr := s.delivery.Deliver(ctx, DeliverInput{
		Client:    client,
		Subject:   subject,
		SessionID: sessionID,
	})
	out := &ReplayResult{}
	if result != nil {
		out.HTTPStatus = result.Status
		out.Delivered = result.Delivered
	}
	// The replay path's "new delivery row" is the one
	// BackchannelLogoutService.Deliver just inserted via the
	// durable-delivery code path. We surface the original row's
	// ID here so the operator dashboard can correlate; we cannot
	// surface the new row's ID because Deliver does not expose it
	// — a future telemetry slice can add a hook.
	out.NewDeliveryID = row.ID
	return out, delivErr
}
