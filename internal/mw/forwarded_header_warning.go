package mw

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/logger"
)

// maxWarnedPeers bounds the memory of the once-per-peer set; past it the
// oldest peer is forgotten, so a new peer is still warned about.
const maxWarnedPeers = 64

// maxForwardedWarningsPerMinute keeps a flood of peers out of the log.
const maxForwardedWarningsPerMinute = 10

// warnForwardedHeaderIgnored tells the operator that a peer sent a forwarding
// header it is not trusted to send. A variable so a test can observe it.
var warnForwardedHeaderIgnored = func(ctx context.Context, peer string) {
	logger.Security.WarnContext(ctx, "X-Forwarded-For ignored: the peer is not a trusted proxy, so every user behind it shares its address (and its rate limits and sign-in lockout); list the proxy in IDENTUUM_IDP_TRUSTED_PROXIES",
		zap.String("event_type", "forwarded_header_ignored"),
		zap.String("peer", peer),
	)
}

// forwardedWarnNow is the clock of the warning rate. A variable so a test can
// fix it.
var forwardedWarnNow = time.Now

// SetForwardedHeaderWarnForTest replaces the warning sink and returns the
// function that restores it. For tests only.
func SetForwardedHeaderWarnForTest(f func(ctx context.Context, peer string)) (restore func()) {
	prev := warnForwardedHeaderIgnored
	warnForwardedHeaderIgnored = f
	return func() { warnForwardedHeaderIgnored = prev }
}

// setForwardedWarnClockForTest replaces the rate's clock and returns the
// function that restores it.
func setForwardedWarnClockForTest(now func() time.Time) (restore func()) {
	prev := forwardedWarnNow
	forwardedWarnNow = now
	return func() { forwardedWarnNow = prev }
}

// ForwardedHeaderWarning warns, once per peer, when a request carries a
// forwarding header that gin ignored because the peer is not a trusted proxy. The
// default (trust no proxy) is right against a forged header; it is wrong for a
// deployment behind a reverse proxy the operator forgot to list, and nothing else
// says why every sign-in appears to come from one address. It remembers the last
// maxWarnedPeers peers and warns at most maxForwardedWarningsPerMinute times a
// minute.
func ForwardedHeaderWarning() gin.HandlerFunc {
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var order []string // seen's peers, oldest first
	var windowStart time.Time
	var inWindow int
	return func(c *gin.Context) {
		if c.GetHeader("X-Forwarded-For") != "" || c.GetHeader("X-Real-IP") != "" {
			peer, _, err := net.SplitHostPort(c.Request.RemoteAddr)
			if err == nil && c.ClientIP() == peer {
				mu.Lock()
				fresh := false
				if _, done := seen[peer]; !done {
					now := forwardedWarnNow()
					if now.Sub(windowStart) >= time.Minute {
						windowStart, inWindow = now, 0
					}
					if inWindow < maxForwardedWarningsPerMinute {
						inWindow++
						fresh = true
						if len(order) == maxWarnedPeers {
							delete(seen, order[0])
							order = order[1:]
						}
						seen[peer] = struct{}{}
						order = append(order, peer)
					}
				}
				mu.Unlock()
				if fresh {
					warnForwardedHeaderIgnored(c.Request.Context(), peer)
				}
			}
		}
		c.Next()
	}
}
