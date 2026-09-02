package service

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// TokenRevocationCleanup is the periodic driver that prunes
// expired rows from `oauth_token_revocations`. The driver is
// deliberately tiny — one ticker loop, one DeleteExpired call per
// tick — so it can be reasoned about without context.
//
// Lifecycle: Run blocks until ctx is cancelled. Operators wire it
// behind a goroutine in main.go; clean shutdown is the ctx-Done
// branch.
//
// The driver logs counts ONLY via the supplied Logger seam. No
// jti values, no metadata, no DB URLs ever land in log lines.
type TokenRevocationCleanup struct {
	svc                *TokenRevocationService
	refreshes          *RefreshTokenService
	replays            *ClientAssertionReplayService
	dpopReplays        *DPoPProofReplayService
	userSessions       *UserSessionService
	authCodes          *AuthorizationCodeService
	loginRisk          *LoginRiskService
	browserTokens      *BrowserSessionTokenService
	backchannelLogouts *BackchannelLogoutService
	oidcStates         OIDCStateSweeper
	passwordResets     ExpiredRowSweeper
	emailVerifications ExpiredRowSweeper
	claims             ExpiredRowSweeper
	mfaPending         ExpiredRowSweeper
	auditEvents        ExpiredRowSweeper
	interval           time.Duration
	logger             CleanupLogger
	newTimer           func(time.Duration) Timer
}

// ExpiredRowSweeper is the narrow seam (mirroring OIDCStateSweeper) for a
// table whose expired rows are pruned each tick via a DeleteExpired that
// returns the affected-row count. The pgx repositories for
// password_resets, email_verifications, organization_claims, and
// mfa_pending_login_sessions satisfy it (P2-12) — these four were never
// swept before, so expired token hashes and the candidate encrypted TOTP
// seed + recovery-code hashes of abandoned enrollments accumulated forever.
type ExpiredRowSweeper interface {
	DeleteExpired(ctx context.Context) (int64, error)
}

// OIDCStateSweeper is the narrow seam for pruning expired oidc_states rows.
// repository.OIDCStateRepository (and its Pgx implementation) satisfies it.
type OIDCStateSweeper interface {
	DeleteExpired(ctx context.Context) (int64, error)
}

// WithOIDCStateSweeper composes expired upstream-OIDC login-state cleanup into
// the driver so each tick also prunes abandoned oidc_states rows (states whose
// login flow was started but never completed at the callback). nil resets to
// the previous composition. Returns the receiver so the call composes with
// construction.
func (c *TokenRevocationCleanup) WithOIDCStateSweeper(s OIDCStateSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.oidcStates = s
	return c
}

// WithPasswordResetSweeper composes expired password_resets cleanup into
// the driver so each tick also prunes reset-token-hash rows past their
// expiry. nil resets to the previous composition. Returns the receiver.
func (c *TokenRevocationCleanup) WithPasswordResetSweeper(s ExpiredRowSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.passwordResets = s
	return c
}

// WithEmailVerificationSweeper composes expired email_verifications
// cleanup into the driver so each tick also prunes verification-token-hash
// rows past their expiry. nil resets to the previous composition.
func (c *TokenRevocationCleanup) WithEmailVerificationSweeper(s ExpiredRowSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.emailVerifications = s
	return c
}

// WithClaimSweeper composes expired organization_claims cleanup into the
// driver so each tick also prunes org-admin delegation-token rows past
// their expiry. nil resets to the previous composition.
func (c *TokenRevocationCleanup) WithClaimSweeper(s ExpiredRowSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.claims = s
	return c
}

// WithMFAPendingSweeper composes expired mfa_pending_login_sessions
// cleanup into the driver so each tick also prunes abandoned enrollment /
// verify handles past their expiry — evicting the candidate encrypted
// TOTP seed + recovery-code hashes those rows retain. nil resets to the
// previous composition.
func (c *TokenRevocationCleanup) WithMFAPendingSweeper(s ExpiredRowSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.mfaPending = s
	return c
}

// WithAuditSweeper composes the OSS plain persistent audit-log retention
// prune into the driver so each tick also deletes audit_events rows older
// than the configured window (L-2). nil resets to the previous composition.
// The sweeper's own retention (non-positive disables pruning) lives on the
// audit repo, not here.
func (c *TokenRevocationCleanup) WithAuditSweeper(s ExpiredRowSweeper) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.auditEvents = s
	return c
}

// WithBackchannelLogoutService composes the backchannel-logout
// delivery-row cleanup into the driver so each tick also prunes
// old `backchannel_logout_deliveries` rows.
func (c *TokenRevocationCleanup) WithBackchannelLogoutService(svc *BackchannelLogoutService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.backchannelLogouts = svc
	return c
}

// WithBrowserSessionTokenService composes the browser-cookie-
// indirection cleanup into the driver so each tick also prunes
// expired browser_session_tokens rows.
func (c *TokenRevocationCleanup) WithBrowserSessionTokenService(svc *BrowserSessionTokenService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.browserTokens = svc
	return c
}

// WithLoginRiskService composes a LoginRiskService into the
// cleanup driver so each tick also prunes expired login_attempts
// rows. nil resets to the previous composition.
//
// Returns the receiver so the call composes with construction.
func (c *TokenRevocationCleanup) WithLoginRiskService(svc *LoginRiskService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.loginRisk = svc
	return c
}

// WithAuthorizationCodeService composes an AuthorizationCodeService
// into the cleanup driver so each tick also prunes expired auth
// codes. nil resets to the previous composition.
//
// Returns the receiver so the call composes with construction.
func (c *TokenRevocationCleanup) WithAuthorizationCodeService(svc *AuthorizationCodeService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.authCodes = svc
	return c
}

// WithUserSessionService composes a UserSessionService into the
// cleanup driver so each tick also prunes expired sessions from
// the sessions table. nil resets to the previous composition.
//
// Returns the receiver so the call composes with construction.
func (c *TokenRevocationCleanup) WithUserSessionService(svc *UserSessionService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.userSessions = svc
	return c
}

// WithClientAssertionReplayService composes a
// ClientAssertionReplayService into the cleanup driver so each
// tick also prunes the oauth_client_assertion_replays table.
// nil resets to the previous composition.
//
// Returns the receiver so the call composes with construction.
func (c *TokenRevocationCleanup) WithClientAssertionReplayService(svc *ClientAssertionReplayService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.replays = svc
	return c
}

// WithDPoPProofReplayService adds the AYGHU-3 DPoP proof replay store to the
// sweep (a separate table from the client-assertion replays).
func (c *TokenRevocationCleanup) WithDPoPProofReplayService(svc *DPoPProofReplayService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.dpopReplays = svc
	return c
}

// WithRefreshTokenService composes a RefreshTokenService into the
// cleanup driver so each tick prunes BOTH oauth_token_revocations
// AND oauth_refresh_tokens. nil resets to "revocation-only"
// behavior, which is the pre-this-slice default.
//
// Returns the receiver so the call composes with construction.
func (c *TokenRevocationCleanup) WithRefreshTokenService(rts *RefreshTokenService) *TokenRevocationCleanup {
	if c == nil {
		return nil
	}
	c.refreshes = rts
	return c
}

// CleanupLogger is the operator-visible log seam. The default
// implementation is NoopCleanupLogger so callers that don't want
// any log output can pass nil. The logger MUST NOT receive raw
// jti values, metadata, secrets, or DB URLs.
type CleanupLogger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
}

// NoopCleanupLogger swallows every emission. Useful for tests
// and for deployments that route logging through their own
// channels (gin.Recovery, stdlib logger, zap).
type NoopCleanupLogger struct{}

// Info implements CleanupLogger.
func (NoopCleanupLogger) Info(string, ...any) {}

// Warn implements CleanupLogger.
func (NoopCleanupLogger) Warn(string, ...any) {}

// Timer is the seam the driver consumes so tests can drive the
// loop with a fake clock. time.Ticker satisfies a thin shim
// returned by realTimer.
type Timer interface {
	// C returns the channel that ticks at the configured interval.
	C() <-chan time.Time
	// Stop releases the underlying ticker.
	Stop()
}

type realTimer struct {
	t *time.Ticker
}

func (r *realTimer) C() <-chan time.Time { return r.t.C }
func (r *realTimer) Stop()               { r.t.Stop() }

// NewTokenRevocationCleanup constructs a cleanup driver.
//
//   - svc is required. A nil svc panics so a misconfigured
//     deployment cannot silently no-op.
//   - interval governs the tick cadence. A non-positive value
//     means "cleanup disabled" — Run returns immediately on
//     start. Operators wiring this from a CLI flag default to a
//     conservative interval (e.g. 1h) and use 0 to opt out.
//   - logger may be nil; NoopCleanupLogger is substituted.
func NewTokenRevocationCleanup(report *lifecycle.StartupReport, svc *TokenRevocationService, interval time.Duration, logger CleanupLogger) *TokenRevocationCleanup {
	if svc == nil {
		report.Fatal("NewTokenRevocationCleanup", "service: NewTokenRevocationCleanup requires a non-nil TokenRevocationService")
	}
	if logger == nil {
		logger = NoopCleanupLogger{}
	}
	return &TokenRevocationCleanup{
		svc:      svc,
		interval: interval,
		logger:   logger,
		newTimer: func(d time.Duration) Timer { return &realTimer{t: time.NewTicker(d)} },
	}
}

// Enabled reports whether the configured interval is positive.
// Operators can use this to skip the goroutine spawn entirely
// when cleanup is disabled.
func (c *TokenRevocationCleanup) Enabled() bool {
	return c != nil && c.interval > 0
}

// Run blocks until ctx is cancelled, calling
// TokenRevocationService.DeleteExpired on every tick. Returns
// immediately when interval is non-positive.
//
// The function is safe to call multiple times sequentially. It
// is NOT safe to call concurrently — operators should spawn one
// goroutine per cleanup driver.
func (c *TokenRevocationCleanup) Run(ctx context.Context) {
	if c == nil || c.interval <= 0 {
		return
	}
	timer := c.newTimer(c.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C():
			c.tick(ctx)
		}
	}
}

// Tick runs one cleanup pass synchronously. Useful for tests
// that want to drive the loop deterministically and for ad-hoc
// operator-initiated cleanup.
func (c *TokenRevocationCleanup) Tick(ctx context.Context) {
	c.tick(ctx)
}

func (c *TokenRevocationCleanup) tick(ctx context.Context) {
	n, err := c.svc.DeleteExpired(ctx)
	if err != nil {
		// Generic error message only. The error value may carry a
		// pgx detail that itself includes the table name; we
		// deliberately do not interpolate it.
		c.logger.Warn("token_revocation_cleanup: delete failed")
	} else if n > 0 {
		c.logger.Info("token_revocation_cleanup: deleted expired rows", "count", n)
	}
	if c.refreshes != nil {
		rn, rerr := c.refreshes.DeleteExpired(ctx)
		if rerr != nil {
			c.logger.Warn("refresh_token_cleanup: delete failed")
		} else if rn > 0 {
			c.logger.Info("refresh_token_cleanup: deleted expired rows", "count", rn)
		}
	}
	if c.replays != nil {
		rn, rerr := c.replays.DeleteExpired(ctx)
		if rerr != nil {
			c.logger.Warn("client_assertion_replay_cleanup: delete failed")
		} else if rn > 0 {
			c.logger.Info("client_assertion_replay_cleanup: deleted expired rows", "count", rn)
		}
	}
	if c.dpopReplays != nil {
		dn, derr := c.dpopReplays.DeleteExpired(ctx)
		if derr != nil {
			c.logger.Warn("dpop_proof_replay_cleanup: delete failed")
		} else if dn > 0 {
			c.logger.Info("dpop_proof_replay_cleanup: deleted expired rows", "count", dn)
		}
	}
	if c.userSessions != nil {
		sn, serr := c.userSessions.DeleteExpired(ctx)
		if serr != nil {
			c.logger.Warn("user_session_cleanup: delete failed")
		} else if sn > 0 {
			c.logger.Info("user_session_cleanup: deleted expired sessions", "count", sn)
		}
	}
	if c.authCodes != nil {
		an, aerr := c.authCodes.DeleteExpired(ctx)
		if aerr != nil {
			c.logger.Warn("authorization_code_cleanup: delete failed")
		} else if an > 0 {
			c.logger.Info("authorization_code_cleanup: deleted expired rows", "count", an)
		}
	}
	if c.loginRisk != nil {
		ln, lerr := c.loginRisk.DeleteExpired(ctx)
		if lerr != nil {
			c.logger.Warn("login_attempts_cleanup: delete failed")
		} else if ln > 0 {
			c.logger.Info("login_attempts_cleanup: deleted expired rows", "count", ln)
		}
	}
	if c.browserTokens != nil {
		bn, berr := c.browserTokens.DeleteExpired(ctx)
		if berr != nil {
			c.logger.Warn("browser_session_tokens_cleanup: delete failed")
		} else if bn > 0 {
			c.logger.Info("browser_session_tokens_cleanup: deleted expired rows", "count", bn)
		}
	}
	if c.oidcStates != nil {
		on, oerr := c.oidcStates.DeleteExpired(ctx)
		if oerr != nil {
			c.logger.Warn("oidc_state_cleanup: delete failed")
		} else if on > 0 {
			c.logger.Info("oidc_state_cleanup: deleted expired rows", "count", on)
		}
	}
	if c.backchannelLogouts != nil {
		dn, derr := c.backchannelLogouts.DeleteExpiredDeliveries(ctx, 0)
		if derr != nil {
			c.logger.Warn("backchannel_logout_deliveries_cleanup: delete failed")
		} else if dn > 0 {
			c.logger.Info("backchannel_logout_deliveries_cleanup: deleted expired rows", "count", dn)
		}
		// Bounded per-tick processing of pending rows whose
		// `next_attempt_at` has elapsed. Re-issues a fresh
		// logout_token via the existing Deliver path; never
		// touches the original token bytes.
		pn, perr := c.backchannelLogouts.ProcessDueDeliveries(ctx, 50)
		if perr != nil {
			c.logger.Warn("backchannel_logout_deliveries_retry: process failed")
		} else if pn > 0 {
			c.logger.Info("backchannel_logout_deliveries_retry: processed due rows", "count", pn)
		}
	}
	if c.passwordResets != nil {
		pn, perr := c.passwordResets.DeleteExpired(ctx)
		if perr != nil {
			c.logger.Warn("password_resets_cleanup: delete failed")
		} else if pn > 0 {
			c.logger.Info("password_resets_cleanup: deleted expired rows", "count", pn)
		}
	}
	if c.emailVerifications != nil {
		en, eerr := c.emailVerifications.DeleteExpired(ctx)
		if eerr != nil {
			c.logger.Warn("email_verifications_cleanup: delete failed")
		} else if en > 0 {
			c.logger.Info("email_verifications_cleanup: deleted expired rows", "count", en)
		}
	}
	if c.claims != nil {
		cn, cerr := c.claims.DeleteExpired(ctx)
		if cerr != nil {
			c.logger.Warn("claims_cleanup: delete failed")
		} else if cn > 0 {
			c.logger.Info("claims_cleanup: deleted expired rows", "count", cn)
		}
	}
	if c.mfaPending != nil {
		mn, merr := c.mfaPending.DeleteExpired(ctx)
		if merr != nil {
			c.logger.Warn("mfa_pending_login_sessions_cleanup: delete failed")
		} else if mn > 0 {
			c.logger.Info("mfa_pending_login_sessions_cleanup: deleted expired rows", "count", mn)
		}
	}
	if c.auditEvents != nil {
		an, aerr := c.auditEvents.DeleteExpired(ctx)
		if aerr != nil {
			c.logger.Warn("audit_events_cleanup: delete failed")
		} else if an > 0 {
			c.logger.Info("audit_events_cleanup: deleted expired rows", "count", an)
		}
	}
}
