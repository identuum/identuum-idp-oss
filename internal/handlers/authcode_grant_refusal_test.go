package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// emptyAuthCodeRepo has no active authorization code, so every Consume sees a
// replayed / unknown / mismatched code and fails invalid_grant.
type emptyAuthCodeRepo struct {
	repository.OAuthAuthorizationCodeRepository
}

func (emptyAuthCodeRepo) GetActiveByCodeHash(context.Context, string, time.Time) (*domain.OAuthAuthorizationCode, error) {
	return nil, nil
}
func (emptyAuthCodeRepo) GetByCodeHashAnyState(context.Context, string) (*domain.OAuthAuthorizationCode, error) {
	return nil, nil
}

// Non-nil no-op lookups: present to satisfy the handler's dependency guard but
// never reached, because Consume refuses the replayed code first.
type nopUserByID struct{}

func (nopUserByID) GetByID(context.Context, uuid.UUID) (*domain.User, error) { return nil, nil }

type nopSessionByID struct{}

func (nopSessionByID) GetByID(context.Context, uuid.UUID) (*domain.Session, error) { return nil, nil }

type nopOrgByID struct{}

func (nopOrgByID) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) { return nil, nil }

// TestHandleAuthorizationCodeGrant_RefusesReplayedCode pins the authorization_code
// grant's single-use gate: an authenticated client presenting a replayed,
// unknown, or mismatched code is refused (a non-nil error), because
// AuthorizationCodeService.Consume finds no active row for it.
// RULE: AUTHCODE-GRANT-REFUSE-1
func TestHandleAuthorizationCodeGrant_RefusesReplayedCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := TokenHandlerDeps{
		AuthCodeService: service.NewAuthorizationCodeService(nil, emptyAuthCodeRepo{}, service.AuthorizationCodeServiceOptions{}),
		UserToken:       &service.UserTokenService{},
		UserLookup:      nopUserByID{},
		SessionLookup:   nopSessionByID{},
		OrgLookup:       nopOrgByID{},
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token",
		strings.NewReader("code=replayed-or-unknown&redirect_uri=https://client.example.com/cb&code_verifier=verifier"))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Inject the authenticated client (mw stores it under this context key).
	c.Set("identuum-oss-oauth-client", &service.AuthenticatedClient{ClientID: "cid"})

	if _, err := handleAuthorizationCodeGrant(c, deps); err == nil {
		t.Errorf("a replayed or unknown authorization code must be refused, got nil error")
	}
}
