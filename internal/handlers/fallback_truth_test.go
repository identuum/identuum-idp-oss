package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// faultUserRepo lets each subtest choose the repo's failure mode.
type faultUserRepo struct {
	*memUserRepo
	updateErr error
	hashErr   error
}

func (r *faultUserRepo) Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	if r.updateErr != nil {
		return nil, r.updateErr
	}
	return r.memUserRepo.Update(ctx, id, orgID, opts)
}

func (r *faultUserRepo) HashPassword(p string) (string, error) {
	if r.hashErr != nil {
		return "", r.hashErr
	}
	return r.memUserRepo.HashPassword(p)
}

// RULE: FALLBACK-TRUTH-1
func TestUpdateFallbackTellsTheTruth(t *testing.T) {
	orgID := uuid.New()
	orgAdmin := &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	run := func(repo repository.UserRepository, targetID uuid.UUID, body string) (int, map[string]any) {
		deps := UsersHandlerDeps{
			Audit:               audit.NoopService{},
			UserService:         service.NewUserService(nil, repo),
			SessionRevoker:      service.NoopSessionRevoker{},
			RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
		}
		return honestRefusalCall(t, orgAdmin, http.MethodPut, "/u/:id", "/u/"+targetID.String(), body, HandleUpdateUser(deps))
	}
	seed := func(repo *memUserRepo) uuid.UUID {
		u := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Email: "f@fallback.test"}
		if _, err := repo.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		return u.ID
	}

	t.Run("an unknown repo error is 500 internal_error, never a 404 lie", func(t *testing.T) {
		repo := &faultUserRepo{memUserRepo: newMemUserRepo(), updateErr: errors.New("disk on fire")}
		id := seed(repo.memUserRepo)
		code, body := run(repo, id, `{"name":"still here"}`)
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown error = %d %v, want 500 internal_error (an outage must not read as a missing user)", code, body)
		}
	})

	t.Run("a hashing failure is the internal fault it is — 500", func(t *testing.T) {
		repo := &faultUserRepo{memUserRepo: newMemUserRepo(), hashErr: errors.New("argon2 exploded")}
		id := seed(repo.memUserRepo)
		code, body := run(repo, id, `{"password":"Perfectly-Fine-Passw0rd!"}`)
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("hashing failure = %d %v, want 500 internal_error", code, body)
		}
	})

	t.Run("duplicate email on update is an honest 409 email_exists", func(t *testing.T) {
		// Enumeration posture: this endpoint is reachable only by
		// site_admin or a SAME-ORG org_admin (cross-org targets are a
		// plain miss before any write). An own-org admin can already
		// LIST every member email, so 409 reveals nothing they cannot
		// read — the same argument bulk's "email already exists"
		// vocabulary has always rested on.
		repo := &faultUserRepo{memUserRepo: newMemUserRepo(), updateErr: domain.ErrUserAlreadyExists}
		id := seed(repo.memUserRepo)
		code, body := run(repo, id, `{"email":"taken@fallback.test"}`)
		if code != http.StatusConflict || body["error"] != "email_exists" {
			t.Fatalf("duplicate email = %d %v, want 409 email_exists", code, body)
		}
	})

	t.Run("404 is reserved for the not-found sentinels — both of them", func(t *testing.T) {
		repo := &faultUserRepo{memUserRepo: newMemUserRepo(), updateErr: domain.ErrUserNotFound}
		id := seed(repo.memUserRepo)
		code, body := run(repo, id, `{"name":"x"}`)
		if code != http.StatusNotFound {
			t.Fatalf("domain not-found sentinel = %d %v, want 404", code, body)
		}
		missing, mb := run(&faultUserRepo{memUserRepo: newMemUserRepo()}, uuid.New(), `{"name":"x"}`)
		if missing != http.StatusNotFound {
			t.Fatalf("service not-found sentinel = %d %v, want 404", missing, mb)
		}
	})
}
