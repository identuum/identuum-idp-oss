package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RULE: USER-ACTIVE-WIRE-1
func TestHandleUpdateUser_ActiveWireTranslatesToBanned(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		initial    bool
		wantBanned bool
	}{
		{name: "deactivate", body: `{"active":false}`, initial: false, wantBanned: true},
		{name: "reactivate", body: `{"active":true}`, initial: true, wantBanned: false},
		{name: "active takes precedence", body: `{"active":true,"banned":true}`, initial: true, wantBanned: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &domain.User{
				ID:             uuid.New(),
				OrganizationID: uuid.New(),
				Role:           domain.RoleOrgUser,
				Email:          "wire-contract@example.test",
				Banned:         tt.initial,
			}
			repo := newMemUserRepo()
			if _, err := repo.Create(context.Background(), user); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			deps := UsersHandlerDeps{
				Audit:               audit.NoopService{},
				UserService:         service.NewUserService(nil, repo),
				SessionRevoker:      service.NoopSessionRevoker{},
				RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
			}

			code := runHandler(t, http.MethodPut, "/u/:id", "/u/"+user.ID.String(), tt.body, HandleUpdateUser(deps))
			if code != http.StatusOK {
				t.Fatalf("update status = %d, want 200", code)
			}

			repo.mu.Lock()
			gotBanned := repo.rows[user.ID].Banned
			repo.mu.Unlock()
			if gotBanned != tt.wantBanned {
				t.Fatalf("active wire field translated to banned = %t, want %t", gotBanned, tt.wantBanned)
			}
		})
	}
}
