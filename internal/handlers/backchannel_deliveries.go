package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// BackchannelDeliveriesHandlerDeps wires the operator admin
// surface for `backchannel_logout_deliveries`.
type BackchannelDeliveriesHandlerDeps struct {
	Admin *service.BackchannelDeliveryAdminService
	Audit audit.Service
}

// RegisterBackchannelDeliveriesRoutes mounts
//
//	GET  /api/v1/admin/backchannel-logout-deliveries
//	GET  /api/v1/admin/backchannel-logout-deliveries/:id
//	POST /api/v1/admin/backchannel-logout-deliveries/:id/replay
//
// All routes site_admin-gated.
func RegisterBackchannelDeliveriesRoutes(router gin.IRouter, deps BackchannelDeliveriesHandlerDeps) {
	if deps.Admin == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/admin/backchannel-logout-deliveries")
	g.Use(mw.RequireSiteAdmin())

	// docgen:endpoint
	// docgen:surface=admin
	// docgen:method=GET
	// docgen:path=/api/v1/admin/backchannel-logout-deliveries
	// docgen:summary=List back-channel logout delivery audit rows (safe projection — never exposes the raw logout_token bytes).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:response=oss.handlers.safeBackchannelDelivery
	// docgen:notes=Response carries no logout_token bytes, no raw cookies, no refresh tokens, no CSRF/MFA material.
	g.GET("", HandleListBackchannelDeliveries(deps))

	// docgen:endpoint
	// docgen:surface=admin
	// docgen:method=GET
	// docgen:path=/api/v1/admin/backchannel-logout-deliveries/:id
	// docgen:summary=Show a single back-channel logout delivery row (safe projection).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:response=oss.handlers.safeBackchannelDelivery
	g.GET("/:id", HandleGetBackchannelDelivery(deps))

	// docgen:endpoint
	// docgen:surface=admin
	// docgen:method=POST
	// docgen:path=/api/v1/admin/backchannel-logout-deliveries/:id/replay
	// docgen:summary=Replay a back-channel logout delivery (re-mints a fresh logout_token; the raw token is never returned to the caller).
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:notes=The fresh logout_token is POSTed to the RP's backchannel_logout_uri server-side; it never enters the admin response body.
	g.POST("/:id/replay", HandleReplayBackchannelDelivery(deps))
}

// safeBackchannelDelivery is the operator-facing DTO. It
// deliberately exposes only fields that are safe at admin scope:
// no logout_token bytes, no raw cookie/refresh tokens, no
// CSRF/MFA/password material. session_id + user_id are exposed at
// site_admin scope (matching the existing admin surfaces).
type safeBackchannelDelivery struct {
	ID            uuid.UUID  `json:"id"`
	ClientID      string     `json:"client_id"`
	SessionID     *uuid.UUID `json:"session_id,omitempty"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	LogoutJTI     string     `json:"logout_jti"`
	Status        string     `json:"status"`
	HTTPStatus    *int       `json:"http_status,omitempty"`
	AttemptCount  int        `json:"attempt_count"`
	LastError     string     `json:"last_error,omitempty"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func toSafeBackchannelDelivery(d *domain.BackchannelLogoutDelivery) safeBackchannelDelivery {
	if d == nil {
		return safeBackchannelDelivery{}
	}
	return safeBackchannelDelivery{
		ID:            d.ID,
		ClientID:      d.ClientID,
		SessionID:     d.SessionID,
		UserID:        d.UserID,
		LogoutJTI:     d.LogoutJTI,
		Status:        string(d.Status),
		HTTPStatus:    d.HTTPStatus,
		AttemptCount:  d.AttemptCount,
		LastError:     d.LastError,
		NextAttemptAt: d.NextAttemptAt,
		DeliveredAt:   d.DeliveredAt,
		CreatedAt:     d.CreatedAt,
		UpdatedAt:     d.UpdatedAt,
	}
}

// HandleListBackchannelDeliveries paginates the table with optional
// `status` and `client_id` filters.
func HandleListBackchannelDeliveries(deps BackchannelDeliveriesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.Query("limit"))
		rows, err := deps.Admin.List(c.Request.Context(), service.ListBackchannelDeliveriesInput{
			Status:   c.Query("status"),
			ClientID: c.Query("client_id"),
			Limit:    limit,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeBackchannelDelivery, 0, len(rows))
		for _, r := range rows {
			out = append(out, toSafeBackchannelDelivery(r))
		}
		c.JSON(http.StatusOK, gin.H{
			"deliveries": out,
			"count":      len(out),
		})
	}
}

// HandleGetBackchannelDelivery returns a single row.
func HandleGetBackchannelDelivery(deps BackchannelDeliveriesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		row, err := deps.Admin.Get(c.Request.Context(), id)
		if err != nil {
			if errors.Is(err, service.ErrBackchannelAdminNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, toSafeBackchannelDelivery(row))
	}
}

// HandleReplayBackchannelDelivery mints a fresh logout_token and
// re-attempts delivery. The operator action is audited with
// `{delivery_id, client_id, status}` only — never the token.
func HandleReplayBackchannelDelivery(deps BackchannelDeliveriesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		result, err := deps.Admin.Replay(c.Request.Context(), id)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrBackchannelAdminNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, service.ErrBackchannelAdminClientGone):
				c.JSON(http.StatusConflict, gin.H{"error": "client_gone"})
			case errors.Is(err, service.ErrBackchannelAdminClientLookupMissing):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "client_lookup_unavailable"})
			default:
				// Delivery itself can return
				// ErrBackchannelDeliveryFailed — that's not a
				// fatal admin-side error; we still surface the
				// row so the operator dashboard updates.
				_ = deps.Audit.Record(c.Request.Context(), audit.Event{
					Action:    "backchannel_logout_delivery.replayed",
					Outcome:   "delivery_failed",
					IPAddress: c.ClientIP(),
					UserAgent: c.Request.UserAgent(),
					Metadata: map[string]any{
						"delivery_id": id.String(),
					},
				})
				if result != nil {
					c.JSON(http.StatusAccepted, gin.H{
						"delivered":   false,
						"http_status": result.HTTPStatus,
					})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "delivery_failed"})
			}
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "backchannel_logout_delivery.replayed",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"delivery_id": id.String(),
				"http_status": result.HTTPStatus,
			},
		})
		c.JSON(http.StatusOK, gin.H{
			"delivered":       result.Delivered,
			"http_status":     result.HTTPStatus,
			"new_delivery_id": result.NewDeliveryID,
		})
	}
}
