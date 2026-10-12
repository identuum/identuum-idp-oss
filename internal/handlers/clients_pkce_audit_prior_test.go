package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// R4 (review OSS-PKCE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-3): the audit of a
// "PKCE required" change must never carry an old value the update did not
// read. The handler used to read the client a second time for the audit's
// before value, start from "required" and keep it when that read failed or
// found nothing; the update then re-read the row and could succeed, so a
// change false -> true was recorded as true -> true. The before value now
// comes from the row the update itself read and changed; a read that fails
// refuses the update before anything is written.

// pkceAuditFaultRepo is the in-memory client store with one read (1-based,
// counted across every GetClientByID) that fails, or finds nothing, and the
// rows handed out as copies, as a real store does.
type pkceAuditFaultRepo struct {
	*memClientRepo
	failRead int
	notFound bool
	reads    int
	updates  int
}

func (r *pkceAuditFaultRepo) GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	r.reads++
	if r.reads == r.failRead {
		if r.notFound {
			return nil, nil
		}
		return nil, errors.New("client store read failed")
	}
	c, err := r.memClientRepo.GetClientByID(ctx, id)
	if c == nil || err != nil {
		return c, err
	}
	cp := *c
	return &cp, nil
}

func (r *pkceAuditFaultRepo) Update(ctx context.Context, c *domain.Client) error {
	r.updates++
	return r.memClientRepo.Update(ctx, c)
}

// MutateClient (C1) reads and writes through the counting, failing methods
// above, so the injected read fault still reaches the update's own read.
func (r *pkceAuditFaultRepo) MutateClient(ctx context.Context, id uuid.UUID, _ *uuid.UUID, fn func(*domain.Client) error) (*domain.Client, *domain.Client, error) {
	return mutateClientByReadAndWrite(ctx, r, id, fn)
}

func TestUpdateClient_PKCEAuditNeverInventsTheOldValueWhenAReadFails(t *testing.T) {
	for _, fault := range []struct {
		name     string
		failRead int
		notFound bool
	}{
		{"the read after the organization check fails", 2, false},
		{"the read after the organization check finds nothing", 2, true},
		{"the third read fails", 3, false},
		{"the third read finds nothing", 3, true},
	} {
		t.Run(fault.name, func(t *testing.T) {
			gin.SetMode(gin.ReleaseMode)
			admin := tenantAdminOf(uuid.New())
			repo := &pkceAuditFaultRepo{memClientRepo: newMemClientRepo()}
			rec := &audit.Recorder{}
			r := gin.New()
			r.Use(mw.InjectPrincipalForTest(admin))
			RegisterClientsRoutes(r, ClientsHandlerDeps{
				ClientService:      service.NewClientService(nil, repo),
				Audit:              rec,
				ClientTokenRevoker: &fakeClientTokenRevoker{},
			})
			e := skipConsentEngine{r: r, repo: repo.memClientRepo, rec: rec, admin: admin}
			id := e.seedPublicClient(false)
			e.repo.rows[id].PKCEOptOut = true
			repo.failRead = fault.failRead
			repo.notFound = fault.notFound

			st, _ := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"pkce_required":true}`)
			var updated []audit.Event
			for _, ev := range rec.Events() {
				if ev.Action == "client.updated" {
					updated = append(updated, ev)
				}
			}
			if st == http.StatusOK {
				// The change went through: its audit names the real before value.
				if len(updated) != 1 || updated[0].Metadata["pkce_required_before"] != false || updated[0].Metadata["pkce_required_after"] != true {
					t.Fatalf("= 200 with client.updated %+v; want exactly one event with before false, after true", updated)
				}
				return
			}
			// Refused: nothing written, nothing audited as changed.
			if repo.updates != 0 || !e.repo.rows[id].PKCEOptOut || len(updated) != 0 {
				t.Errorf("= %d with %d repository updates, stored opt-out %v, client.updated %+v; want a refusal that writes and audits nothing",
					st, repo.updates, e.repo.rows[id].PKCEOptOut, updated)
			}
			if !fault.notFound && st != http.StatusServiceUnavailable {
				t.Errorf("a failed store read = %d; want the store-unavailable 503", st)
			}
		})
	}
}
