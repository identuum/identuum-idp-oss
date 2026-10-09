package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// OSS-BACKCHANNEL-TEST-SEAM: registration requires an https
// backchannel_logout_uri. Only the TEST switch wired by
// IDENTUUM_IDP_TEST_ALLOW_PRIVATE_BACKCHANNEL_RECEIVER accepts a plain-http
// receiver, on create and on update; the front-channel URI stays strict.

// updateRecordingClientRepo serves one stored client and records the update.
type updateRecordingClientRepo struct {
	repository.ClientRepository
	stored      *domain.Client
	updateCalls int
	last        *domain.Client
}

func (r *updateRecordingClientRepo) GetClientByID(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
	cp := *r.stored
	return &cp, nil
}

func (r *updateRecordingClientRepo) Update(_ context.Context, c *domain.Client) error {
	r.updateCalls++
	r.last = c
	return nil
}

func TestClientService_PlainHTTPBackchannelReceiverOnlyWithTheTestSwitch(t *testing.T) {
	const httpReceiver = "http://localhost:9500/backchannel-logout"
	base := func() RegisterClientOptions {
		return RegisterClientOptions{
			Name:                 "Billing Portal",
			RedirectURIs:         []string{"https://app.example.test/cb"},
			BackchannelLogoutURI: httpReceiver,
		}
	}

	t.Run("create: refused by default", func(t *testing.T) {
		repo := &registerRecordingClientRepo{}
		_, _, err := NewClientService(nil, repo).RegisterClient(context.Background(), base())
		if !errors.Is(err, domain.ErrInvalidRequest) {
			t.Fatalf("err = %v; want invalid_request for a plain-http backchannel_logout_uri", err)
		}
		if repo.registerCalls != 0 {
			t.Errorf("the repository was called %d time(s) with a refused client", repo.registerCalls)
		}
	})

	t.Run("create: accepted with the switch", func(t *testing.T) {
		repo := &registerRecordingClientRepo{}
		svc := NewClientService(nil, repo).WithPlainHTTPBackchannelLogoutURIs()
		if _, _, err := svc.RegisterClient(context.Background(), base()); err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
		if repo.registerCalls != 1 || repo.last == nil || repo.last.BackchannelLogoutURI != httpReceiver {
			t.Errorf("register calls = %d, stored uri = %q", repo.registerCalls, func() string {
				if repo.last == nil {
					return ""
				}
				return repo.last.BackchannelLogoutURI
			}())
		}
	})

	t.Run("create: the switch leaves the front-channel uri strict", func(t *testing.T) {
		repo := &registerRecordingClientRepo{}
		svc := NewClientService(nil, repo).WithPlainHTTPBackchannelLogoutURIs()
		opts := base()
		opts.BackchannelLogoutURI = ""
		opts.FrontchannelLogoutURI = "http://localhost:9500/frontchannel-logout"
		if _, _, err := svc.RegisterClient(context.Background(), opts); !errors.Is(err, domain.ErrInvalidRequest) {
			t.Fatalf("err = %v; want invalid_request for a plain-http frontchannel_logout_uri", err)
		}
		if repo.registerCalls != 0 {
			t.Errorf("the repository was called %d time(s) with a refused client", repo.registerCalls)
		}
	})

	stored := func() *domain.Client {
		return &domain.Client{
			ID:                      uuid.New(),
			ClientID:                "cli-1",
			Name:                    "Billing Portal",
			RedirectURIs:            []string{"https://app.example.test/cb"},
			TokenEndpointAuthMethod: "client_secret_basic",
		}
	}
	uri := httpReceiver

	t.Run("update: refused by default", func(t *testing.T) {
		repo := &updateRecordingClientRepo{stored: stored()}
		_, err := NewClientService(nil, repo).UpdateClient(context.Background(), repo.stored.ID, UpdateClientOptions{BackchannelLogoutURI: &uri})
		if !errors.Is(err, domain.ErrInvalidRequest) {
			t.Fatalf("err = %v; want invalid_request for a plain-http backchannel_logout_uri", err)
		}
		if repo.updateCalls != 0 {
			t.Errorf("the repository was updated %d time(s) with a refused uri", repo.updateCalls)
		}
	})

	t.Run("update: accepted with the switch", func(t *testing.T) {
		repo := &updateRecordingClientRepo{stored: stored()}
		svc := NewClientService(nil, repo).WithPlainHTTPBackchannelLogoutURIs()
		if _, err := svc.UpdateClient(context.Background(), repo.stored.ID, UpdateClientOptions{BackchannelLogoutURI: &uri}); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
		if repo.updateCalls != 1 || repo.last == nil || repo.last.BackchannelLogoutURI != httpReceiver {
			t.Errorf("update calls = %d; stored uri not the plain-http receiver", repo.updateCalls)
		}
	})
}
