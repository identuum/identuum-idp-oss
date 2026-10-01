package handlers

// organization_claim.go — OSS-CLAIM (owner ruling D-022): a site_admin issues
// a one-time organization claim link.
//
//   POST /api/v1/organizations/:id/claim  {email?}
//     201 {claim_url, expires_at, email_bound}  — the link is shown once
//     409 {"error":"organization_not_claimable"} — an active org_admin
//         exists, or the organization is inactive or deleted
//     409 {"error":"claim_url_unavailable", "claim_url_unavailable": why}
//         — no UI base URL: no link can be built, so nothing is issued
//     404 unknown organization; 400 malformed id or email
//
// The raw token appears only inside claim_url in this response; no log line
// and no audit row carries it.

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OrgClaimIssuer issues an organization claim link
// (implemented by *service.ClaimService).
type OrgClaimIssuer interface {
	IssueClaim(ctx context.Context, in service.IssueClaimInput) (*service.IssuedClaim, error)
}

func claimLinkUnavailableReason() string {
	return "no claim link can be built because " + activationLinkSettingName +
		" is not set; set it to the browser-facing base URL of the identuum-ui " +
		"frontend (for example http://localhost:7104) and issue the link again"
}

// HandleIssueOrganizationClaim serves POST /api/v1/organizations/:id/claim.
func HandleIssueOrganizationClaim(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.ClaimIssuer == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "claim issuance unavailable"})
			return
		}
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Email string `json:"email"`
		}
		if c.Request.ContentLength != 0 {
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
				return
			}
		}
		email := strings.TrimSpace(req.Email)
		if email != "" {
			if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email"})
				return
			}
		}
		// Refuse before issuing: a link nobody can open is not handed over,
		// and no claim row is left behind.
		if strings.TrimSpace(deps.ActivationLinkBaseURL) == "" {
			c.JSON(http.StatusConflict, gin.H{"error": "claim_url_unavailable", "claim_url_unavailable": claimLinkUnavailableReason()})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		issued, err := deps.ClaimIssuer.IssueClaim(c.Request.Context(), service.IssueClaimInput{
			OrganizationID: orgID, Email: email, Actor: actor,
			IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(),
		})
		switch {
		case errors.Is(err, domain.ErrOrganizationNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		case errors.Is(err, service.ErrClaimOrgNotClaimable):
			c.JSON(http.StatusConflict, gin.H{"error": "organization_not_claimable"})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"claim_url":   uiTokenLink(deps.ActivationLinkBaseURL, "/claim", issued.Token),
			"expires_at":  issued.ExpiresAt.UTC().Format(time.RFC3339),
			"email_bound": issued.EmailBound,
		})
	}
}
