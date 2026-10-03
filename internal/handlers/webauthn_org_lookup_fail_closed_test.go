package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// erroringUserOrgLookup fails the org-policy reload.
type erroringUserOrgLookup struct{}

func (erroringUserOrgLookup) GetByIDWithOrg(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, errors.New("store unavailable")
}

// When the organization policy cannot be read, passkey sign-in is refused
// (503) rather than completed under permissive defaults, and no session is
// created.
func TestWebAuthnFinish_OrgPolicyLookupErrorFailsClosed(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "lk@x.test"}
	deps := r2Deps(user, true)
	deps.UserOrgLookup = erroringUserOrgLookup{}
	code, body := r2RunFinish(deps)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503 when the org policy cannot be read", code)
	}
	// The body is never echoed: on failure it can carry token values.
	if strings.Contains(body, "session_id") || strings.Contains(body, "refresh_token") {
		t.Error("no session or token may be issued")
	}
}
