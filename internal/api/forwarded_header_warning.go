package api

import (
	"context"
	"net"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/logger"
)

// maxWarnedPeers bounds the memory of the once-per-peer set; a peer past it is
// not warned about.
const maxWarnedPeers = 64

// warnForwardedHeaderIgnored tells the operator that a peer sent a forwarding
// header it is not trusted to send. A variable so a test can observe it.
var warnForwardedHeaderIgnored = func(ctx context.Context, peer string) {
	logger.Security.WarnContext(ctx, "X-Forwarded-For ignored: the peer is not a trusted proxy, so every user behind it shares its address (and its rate limits and sign-in lockout); list the proxy in IDENTUUM_IDP_TRUSTED_PROXIES",
		zap.String("event_type", "forwarded_header_ignored"),
		zap.String("peer", peer),
	)
}

// mountForwardedHeaderWarning warns, once per peer, when a request carries a
// forwarding header that gin ignored because the peer is not a trusted proxy. The
// default (trust no proxy) is right against a forged header; it is wrong for a
// deployment behind a reverse proxy the operator forgot to list, and nothing else
// says why every sign-in appears to come from one address.
func mountForwardedHeaderWarning(router gin.IRouter) {
	var mu sync.Mutex
	seen := make(map[string]struct{})
	router.Use(func(c *gin.Context) {
		if c.GetHeader("X-Forwarded-For") != "" || c.GetHeader("X-Real-IP") != "" {
			peer, _, err := net.SplitHostPort(c.Request.RemoteAddr)
			if err == nil && c.ClientIP() == peer {
				mu.Lock()
				_, done := seen[peer]
				fresh := !done && len(seen) < maxWarnedPeers
				if fresh {
					seen[peer] = struct{}{}
				}
				mu.Unlock()
				if fresh {
					warnForwardedHeaderIgnored(c.Request.Context(), peer)
				}
			}
		}
		c.Next()
	})
}
