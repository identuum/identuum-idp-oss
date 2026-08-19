// Package runtime hosts the production-shaped Gin OSS runtime
// lifecycle. It is the implementation-side authority that the public
// pkg/runtime seam re-exports.
//
// The public seam owns the stable import surface CE pins against;
// this package owns the behaviour. Both surfaces describe the same
// in-process IDP runtime — open a Postgres pool (if configured), wire
// the OSS service layer + repository factory, mount the OSS Gin
// route surface, and run a graceful HTTP server with a background
// jti / refresh-token cleanup driver.
//
// R1 scope (boundary contract — see wiki/repos/identuum-idp-oss.md
// §"pkg/runtime"):
//
//   - Runtime is the SOLE surface this package exports for
//     downstream lifecycle control. Start opens DB, wires services,
//     and begins serving; Shutdown drains. The pgxpool.Pool, the
//     repository.* interfaces, and the internal/service.* types are
//     intentionally NOT exposed via accessors — those remain
//     internal so CE composes through the route seam, not by
//     reaching into runtime guts.
//   - Migrations are NOT executed by Start. Operators run
//     `identuum-idp --migrate <url>` separately; the runtime expects
//     the DB schema to already be at the OSS embedded version.
//   - The public seam (pkg/runtime) is a thin alias/shim over this
//     package. Changing this package's behaviour changes the public
//     behaviour; the alias never adds or hides logic.
//
// SECURITY contract:
//
//   - The operator-supplied JWKSDBURL is NEVER printed to Stdout or
//     Stderr. Errors that may embed the URL are scrubbed via
//     redactURL before being returned or logged.
//   - The CSRF HMAC key, signing keys, raw refresh tokens, raw JWTs,
//     and any other secret material stay inside the internal
//     service layer. The runtime never logs or exposes them.
//   - Runtime carries no license envelope and never imports
//     identuum-idp-ce.
package runtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/identuum/identuum-idp-oss/internal/startup"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/auth"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
	"github.com/identuum/identuum-idp-oss/internal/lease"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
	"github.com/identuum/identuum-idp-oss/logger"
)

// Config is the operator-facing configuration for the OSS runtime.
//
// All fields except Addr are optional. A zero Config (other than
// Addr) yields the "no JWKS DB" lifecycle: a Gin engine with
// /system/info, /health, /metrics, and the empty-JWKS discovery
// surface registered, no OAuth / RBAC / OIDC route groups, no DB
// pool, no cleanup goroutine.
type Config struct {
	// Addr is the TCP listener bind address (e.g. "127.0.0.1:7113"
	// or "0.0.0.0:8080"). An empty Addr causes New to fail.
	Addr string

	// Issuer is the OIDC issuer URL advertised in
	// /.well-known/openid-configuration and used as the token /
	// ID-token issuer claim. May be empty — the runtime substitutes
	// "http://localhost" when an issuer is needed downstream.
	Issuer string

	// JWKSDBURL is the operator-supplied Postgres connection string.
	// When empty the runtime serves only the always-public surface
	// (no DB, no OAuth, no JWKS-from-keys). When non-empty the
	// runtime opens a pgxpool and wires the full OSS service layer
	// from the resulting repository factory.
	//
	// The URL is NEVER printed to Stdout or Stderr. Errors that
	// would embed it are scrubbed before being returned.
	JWKSDBURL string

	// RevocationCleanupInterval governs the cadence of the
	// background token-revocation / refresh-token / replay /
	// session / login-attempt cleanup goroutine. A non-positive
	// value disables cleanup entirely; the goroutine is not
	// spawned.
	RevocationCleanupInterval time.Duration

	// Version is the human-readable build identifier surfaced at
	// /system/info and /health. Empty defaults to a generic OSS
	// runtime tag — the cmd entrypoint typically passes its own
	// version string here.
	Version string

	// Stdout receives operator-visible status messages: listener
	// address, JWKS-DB readiness, cleanup driver start, shutdown
	// signal handling. nil is replaced with io.Discard.
	Stdout io.Writer

	// Stderr receives operator-visible error messages. nil is
	// replaced with io.Discard.
	Stderr io.Writer

	// Getenv is the env-var lookup hook consumed by
	// resolveUIPublicBaseURLForWebAuthn. nil is replaced with
	// os.Getenv. Tests can inject a hermetic stub.
	Getenv func(string) string

	// DataDir is the persistent data directory the IDP owns per
	// appliance install UX decision D-IDP-INSTALL-21. The first-run
	// setup foundation reads/writes $DataDir/setup-token.txt (mode
	// 0600) while status == setup_required. Empty defaults to "."
	// (current working directory) — operators running under
	// `docker compose` typically mount a named volume here.
	DataDir string

	// UIPublicBaseURL is the browser-facing base URL of the
	// identuum-ui surface (e.g. http://localhost:7104). Used by the
	// setup boot banner to render the "open the wizard at <URL>"
	// hint. Empty falls back to Issuer.
	UIPublicBaseURL string

	// MetricsAddr is the TCP listener bind address for the
	// Prometheus /metrics endpoint, served on its OWN listener —
	// separate from Addr (the public API surface). This closes the
	// tenant/IDP-enumeration exposure noted in
	// docs/audit/changelog/security-headers-middleware.md (some
	// metric labels — org_id, provider_id, provider_name — are safe
	// for an internal-only scrape target but not for the public API
	// port). Empty disables the metrics listener entirely (no route
	// is served anywhere) — the default value is chosen by the CLI
	// entrypoint (cmd/identuum-idp), not this package, so existing
	// embedders/tests that construct Config directly are unaffected
	// unless they opt in.
	MetricsAddr string

	// CORSAllowedOrigins is the deny-by-default, EXACT-match CORS
	// origin allowlist handed to the global CORS middleware
	// (internal/mw.CORS). Empty (the default) grants no cross-origin
	// request CORS access — same-origin traffic is unaffected. The CLI
	// entrypoint (cmd/identuum-idp) populates it from
	// IDENTUUM_IDP_CORS_ALLOWED_ORIGINS; embedders/tests that build
	// Config directly leave it empty and get deny-all.
	CORSAllowedOrigins []string

	// TrustedProxies is the operator-supplied trusted reverse-proxy
	// address/CIDR list handed to gin's SetTrustedProxies. Empty (the
	// default) trusts NO proxy, so c.ClientIP() — the IP used by rate
	// limiting AND audit/security-event attribution — is the direct peer
	// and a forged X-Forwarded-For cannot spoof it. The CLI entrypoint
	// (cmd/identuum-idp) populates it from IDENTUUM_IDP_TRUSTED_PROXIES;
	// embedders/tests that build Config directly leave it empty and trust
	// none. Operators fronting the app with a proxy MUST set it or client
	// IPs will be the proxy's.
	TrustedProxies []string
}

// Runtime is the OSS in-process IDP lifecycle handle.
//
// Lifecycle:
//
//	rt, err := runtime.New(cfg)        // validate cfg
//	if err := rt.Start(ctx); err != nil // open DB, wire services, listen, serve
//	<-rt.Done()                        // optional: wait for the serve loop
//	rt.Shutdown(ctx)                   // graceful drain
//
// Start is non-blocking — it returns once the listener is bound and
// the serve goroutine has been launched. Shutdown is idempotent.
// The Runtime is single-use; constructing a new instance is the
// only supported way to restart after Shutdown.
type Runtime struct {
	cfg Config

	// engine is the constructed Gin engine. Populated by Start.
	engine *gin.Engine

	// startupReport is the P-018 NOT-SERVING fault accumulator. Created
	// in Start, injected into the router deps before the engine is built,
	// and retained for the life of the process so /health and the
	// NOT-SERVING guard can re-derive the serving mode on every request.
	// A report carrying a fatal fault means the process is live but
	// refusing normal traffic (NOT-SERVING-JUST-ALERTING).
	startupReport *lifecycle.StartupReport

	// listener is the bound TCP listener. Populated by Start.
	listener net.Listener

	// srv is the http.Server wrapping engine + listener. Populated
	// by Start.
	srv *http.Server

	// metricsListener and metricsSrv are the SEPARATE listener/server
	// pair for /metrics, populated by Start only when
	// Config.MetricsAddr is non-empty AND the bind succeeds. A bind
	// failure leaves both nil — the metrics endpoint is simply not
	// served; the primary IdP is unaffected (P-018: no panic/Fatal/
	// Exit on a serving path).
	metricsListener net.Listener
	metricsSrv      *http.Server

	// pool is the optional pgxpool. nil when Config.JWKSDBURL is
	// empty. Closed by Shutdown.
	pool *pgxpool.Pool

	// leaseCoordinator enforces the OSS single-replica boundary (A-2a):
	// exactly one live instance may serve. nil when the operator set
	// IDENTUUM_IDP_ALLOW_MULTI_REPLICA to knowingly run multi-replica.
	// Released (best-effort) by Shutdown so a successor acquires without
	// waiting out the lease TTL.
	leaseCoordinator *lease.Coordinator

	// cleanupCancel cancels the cleanup goroutine context. nil when
	// cleanup is disabled.
	cleanupCancel context.CancelFunc

	// done is closed once the serve loop returns. serveErr stores
	// the loop's final error (nil for graceful shutdown).
	done      chan struct{}
	serveErr  error
	serveOnce sync.Once

	// shutdownOnce ensures Shutdown is idempotent.
	shutdownOnce sync.Once
	shutdownErr  error
}

// New validates cfg and returns a Runtime. New does NOT open the
// DB, bind the listener, or construct services — those happen in
// Start. A zero Runtime should not be used; always go through New.
func New(cfg Config) (*Runtime, error) {
	if cfg.Addr == "" {
		return nil, errors.New("runtime: Config.Addr is empty")
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.Version == "" {
		cfg.Version = "identuum-idp-oss (unknown version)"
	}
	if cfg.DataDir == "" {
		if env := cfg.Getenv("IDENTUUM_IDP_DATA_DIR"); env != "" {
			cfg.DataDir = env
		} else {
			cfg.DataDir = "."
		}
	}
	if cfg.UIPublicBaseURL == "" {
		if env := cfg.Getenv("IDENTUUM_IDP_UI_PUBLIC_BASE_URL"); env != "" {
			cfg.UIPublicBaseURL = env
		}
	}
	return &Runtime{
		cfg:  cfg,
		done: make(chan struct{}),
	}, nil
}

// Start performs all runtime construction:
//
//   - If Config.JWKSDBURL is non-empty: open a pgxpool, build the
//     OSS repository factory + full service layer, and wire the
//     resulting deps into the Gin route surface.
//   - Otherwise: skip the DB path entirely; the engine serves only
//     the always-public surface.
//   - Bind a TCP listener on Config.Addr.
//   - Start a goroutine running http.Server.Serve(listener). The
//     goroutine writes its terminal error into r.serveErr and
//     closes r.done.
//   - If a TokenRevocationService is wired AND
//     Config.RevocationCleanupInterval is positive: start the
//     cleanup goroutine.
//
// Start is non-blocking. Callers wait on Done() or call Shutdown.
//
// Failure to bind the listener (or any DB / service construction
// error) closes the DB pool and returns the error without leaking
// resources. The returned error never carries the operator-supplied
// JWKSDBURL — pgx errors that embed the URL are scrubbed via
// redactURL.
func (r *Runtime) Start(ctx context.Context) error {
	if r.engine != nil {
		return errors.New("runtime: Start called twice")
	}

	// P3-12: the SERVING process runs with a real zap logger. Before this
	// call the package loggers are nops (logger/logger.go init), which
	// silently discarded 100+ call sites including every ERROR-level fault
	// P-018 requires surfaced and both SOC 2 Security events (SSRF block,
	// rate-limit breach). One-shot operator tools (migrate / bootstrap /
	// recover-site-admin) do NOT pass through here and keep their
	// fmt-based, log-silent UX. Level via AUTH_SERVICE_LOG_LEVEL
	// (default info; debug stays nop unless explicitly enabled).
	logger.InitializeZapLogger()

	// P-018: create the NOT-SERVING fault accumulator BEFORE dependency
	// wiring so the class-C service/verifier constructors can record a
	// fatal fault (instead of panicking) when a required dependency is
	// missing/invalid. The report is retained on the Runtime for the life
	// of the process and injected into the router deps below.
	r.startupReport = lifecycle.NewStartupReport()

	deps, pool, replaySvc, refreshTokenSvc, userSessionSvc,
		authCodeSvc, loginRiskSvc, browserTokenSvc,
		backchannelLogoutSvc, tokenRevocationSvc, oidcStateRepo, retentionSweeps, err := r.buildDeps(ctx, r.startupReport)
	if err != nil {
		return err
	}
	r.pool = pool

	deps.StartupReport = r.startupReport

	// A-2a — enforce the OSS single-replica boundary. identuum-idp-oss is
	// single-replica BY DESIGN: its rate limiting (per-process token-bucket
	// map), WebAuthn ceremony state (in-process map), and CSRF secret
	// (fresh per process) are correct for one replica but SILENTLY BROKEN
	// across replicas. Horizontal scaling / HA is a Professional+
	// commercial capability. A DB-backed singleton lease lets exactly one
	// live instance serve; a loser records a P-018 fatal and enters
	// NOT-SERVING (503) rather than serving with broken per-process
	// security. This runs BEFORE binding the listener so a loser never
	// serves normal traffic during the acquisition window.
	// L-3: the FIPS build attestation finally RUNS. VerifyFIPSBuildOrFail
	// existed with five callers, all in its own test file — the refusal it
	// implements never executed in any process. Opt-in stays opt-in
	// (AUTH_SERVICE_REQUIRE_FIPS, the name its own error message prints, with
	// the repo-preferred IDENTUUM_IDP_REQUIRE_FIPS accepted as an alias), and
	// P-018 governs the failure: a wrong-binary boot records a FATAL and
	// enters NOT-SERVING (503 + loud health) rather than os.Exit — refusing
	// traffic, not killing the process.
	requireFIPS := resolveEnvBool(r.cfg.Getenv, "AUTH_SERVICE_REQUIRE_FIPS") ||
		resolveEnvBool(r.cfg.Getenv, "IDENTUUM_IDP_REQUIRE_FIPS")
	if err := startup.VerifyFIPSBuildOrFail(requireFIPS, debug.ReadBuildInfo, func(msg string) {
		fmt.Fprintf(r.cfg.Stdout, "identuum-idp: serve: %s\n", msg)
	}); err != nil {
		r.startupReport.Fatal("fips-build-attestation", err.Error())
	}

	if resolveAllowMultiReplica(r.cfg.Getenv) {
		// Explicit, KNOWING override — never a silent bypass.
		fmt.Fprint(r.cfg.Stderr,
			"identuum-idp: serve: WARNING IDENTUUM_IDP_ALLOW_MULTI_REPLICA is set — the OSS single-replica lease is DISABLED. "+
				"identuum-idp-oss is single-replica by design; running multiple replicas SILENTLY BREAKS per-process security: "+
				"rate limits are per-process (N replicas grant N× every mounted limit), WebAuthn ceremonies begun on one replica "+
				"cannot finish on another, and each replica generates its own CSRF secret (tokens are not cross-validatable). "+
				"Horizontal scaling / HA is a Professional+ commercial capability. Proceed only if you understand and accept "+
				"this degradation.\n")
	} else {
		leaseRepo := postgres.NewPgxInstanceLeaseRepository(r.pool)
		coord := lease.NewCoordinator(
			leaseRepo,
			lease.Config{InstanceID: lease.NewInstanceID()},
			r.startupReport,
			func(format string, args ...any) {
				fmt.Fprintf(r.cfg.Stderr, "identuum-idp: serve: "+format+"\n", args...)
			},
		)
		r.leaseCoordinator = coord
		if coord.Acquire(ctx) {
			fmt.Fprintf(r.cfg.Stdout,
				"identuum-idp: serve: single-replica instance lease acquired (heartbeat=%s, ttl=%s); OSS is single-replica by design — HA is a Professional+ capability\n",
				lease.DefaultHeartbeat, lease.DefaultTTL)
		}
		// On failure the coordinator has ALREADY recorded a fatal on the
		// StartupReport and logged the loud ERROR. We deliberately keep
		// going (P-018): the engine below mounts the NOT-SERVING guard,
		// announceStartupMode surfaces the fault, and every normal route is
		// refused with 503 while the process stays alive and /livez stays up.
	}

	// First-run setup foundation. Initialize is idempotent: on a
	// freshly migrated database it generates a setup token, writes
	// the plaintext to $DataDir/setup-token.txt, and persists the
	// SHA-256 hash; on subsequent boots while status ==
	// setup_required it reuses the existing token if the file is
	// present and matches, otherwise regenerates. After setup
	// completes it returns a nil banner and no further log lines.
	if deps.SetupService != nil {
		banner, setupErr := deps.SetupService.Initialize(ctx, r.cfg.DataDir)
		if setupErr != nil {
			if r.pool != nil {
				r.pool.Close()
				r.pool = nil
			}
			return fmt.Errorf("runtime: setup initialize: %w", setupErr)
		}
		if banner != nil {
			// Print URL + plaintext setup code + the local
			// show-setup-code subcommand on every boot while
			// status == setup_required. The setup code is the
			// wizard-authorisation credential, not an admin
			// password (D-IDP-INSTALL-19), and is allowed in logs
			// by the appliance install UX decisions
			// (D-IDP-INSTALL-11). Operators with log-retention
			// concerns can run `identuum-idp show-setup-code <data-dir>`
			// to read the file directly.
			fmt.Fprintf(r.cfg.Stdout,
				"identuum-idp: serve: first-run setup required — open %s\n",
				banner.SetupURL)
			fmt.Fprintf(r.cfg.Stdout,
				"identuum-idp: serve: setup code (also stored at %s): %s\n",
				banner.TokenFilePath, banner.SetupToken)
			fmt.Fprintf(r.cfg.Stdout,
				"identuum-idp: serve: to re-display the setup code later, run: %s\n",
				banner.ShowCodeCommand)
		}
	}

	listener, err := net.Listen("tcp", r.cfg.Addr)
	if err != nil {
		if r.pool != nil {
			r.pool.Close()
			r.pool = nil
		}
		return fmt.Errorf("runtime: listen failed: %w", err)
	}
	r.listener = listener

	r.engine = api.NewOSSEngine(deps)

	// P-018 NOT-SERVING-JUST-ALERTING: if route registration / wiring
	// recorded a fatal fault, the process stays alive and keeps listening
	// (so the health probe can report the fault and orchestrators see a
	// live process) but every normal route is refused with 503 by the
	// mounted NotServingGuard. Surface the fault loudly and persistently
	// at ERROR level — never panic / os.Exit.
	r.announceStartupMode()

	r.srv = &http.Server{
		Handler:           r.engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	fmt.Fprintf(r.cfg.Stdout,
		"identuum-idp: serve: OSS IdP listening on %s\n",
		listener.Addr().String())

	// Cleanup driver — only when (a) the service is wired (i.e.
	// JWKSDBURL supplied) AND (b) the interval is positive. The
	// goroutine exits cleanly on ctx-cancel from Shutdown.
	if tokenRevocationSvc != nil && r.cfg.RevocationCleanupInterval > 0 {
		cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
		r.cleanupCancel = cleanupCancel
		cleanup := service.NewTokenRevocationCleanup(r.startupReport, tokenRevocationSvc, r.cfg.RevocationCleanupInterval, &stdoutCleanupLogger{w: r.cfg.Stdout}).
			WithRefreshTokenService(refreshTokenSvc).
			WithClientAssertionReplayService(replaySvc).
			WithUserSessionService(userSessionSvc).
			WithAuthorizationCodeService(authCodeSvc).
			WithLoginRiskService(loginRiskSvc).
			WithBrowserSessionTokenService(browserTokenSvc).
			WithBackchannelLogoutService(backchannelLogoutSvc).
			WithOIDCStateSweeper(oidcStateRepo).
			WithPasswordResetSweeper(retentionSweeps.passwordResets).
			WithEmailVerificationSweeper(retentionSweeps.emailVerifications).
			WithClaimSweeper(retentionSweeps.claims).
			WithMFAPendingSweeper(retentionSweeps.mfaPending).
			WithAuditSweeper(retentionSweeps.audit)
		go cleanup.Run(cleanupCtx)
		fmt.Fprintf(r.cfg.Stdout,
			"identuum-idp: serve: oauth_token_revocations + oauth_refresh_tokens + oauth_client_assertion_replays + sessions + oidc_states + password_resets + email_verifications + organization_claims + mfa_pending_login_sessions + audit_events cleanup driver started (interval=%s)\n",
			r.cfg.RevocationCleanupInterval)
	}

	go func() {
		err := r.srv.Serve(listener)
		r.serveOnce.Do(func() {
			r.serveErr = err
			close(r.done)
		})
	}()

	r.startMetricsListener()

	return nil
}

// startMetricsListener binds the SEPARATE, internal-only /metrics
// listener when Config.MetricsAddr is non-empty. This is the
// topological fix for the tenant/IDP-enumeration exposure noted in
// docs/audit/changelog/security-headers-middleware.md: /metrics never
// shares a listener with the public API surface, so an operator can
// firewall it by port/network alone — no auth gate, no label
// stripping.
//
// P-018: a bind failure here is logged and the metrics endpoint is
// simply not served; it must NEVER panic, Fatal, or Exit, and must
// NEVER prevent the primary IdP listener (already serving by the time
// this runs) from continuing to serve normal traffic.
func (r *Runtime) startMetricsListener() {
	if r.cfg.MetricsAddr == "" {
		return
	}
	metricsListener, err := net.Listen("tcp", r.cfg.MetricsAddr)
	if err != nil {
		fmt.Fprintf(r.cfg.Stderr,
			"identuum-idp: serve: metrics listener bind failed on %s: %v (metrics endpoint will not be served; the IdP continues serving normally)\n",
			r.cfg.MetricsAddr, err)
		return
	}
	r.metricsListener = metricsListener

	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsExporterHandler())
	r.metricsSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	fmt.Fprintf(r.cfg.Stdout,
		"identuum-idp: serve: metrics listening on %s (internal-only, UNAUTHENTICATED, not part of the public API surface; loopback by default — labels carry org/provider IDs, so set --metrics-addr / IDENTUUM_IDP_METRICS_ADDR to a routable address only to deliberately expose it)\n",
		metricsListener.Addr().String())

	go func() {
		_ = r.metricsSrv.Serve(metricsListener)
	}()
}

// metricsExporterHandler returns the REAL Prometheus exposition handler
// for the internal-only metrics listener, replacing the prior
// hardcoded-placeholder response (integrity-audit finding F5: the
// internal/metrics collectors were incrementing into a registry nothing
// served).
//
// Registration model: every collector in internal/metrics is created
// via promauto.New* on package-level vars, which registers it with
// prometheus.DefaultRegisterer exactly once at package init — the
// serving binary imports internal/metrics transitively (api → handlers
// → mw), so all collectors are registered before this handler is built.
// No MustRegister call exists on this path, so a duplicate-registration
// panic is structurally impossible (P-018).
//
// promhttp.HandlerFor is configured with HTTPErrorOnError: a gather
// failure yields a 500 response, never a panic (P-018). The handler
// serves prometheus.DefaultGatherer, which also includes the standard
// go_* / process_* collectors.
func metricsExporterHandler() http.Handler {
	return promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
}

// Done returns a channel closed once the serve loop has returned.
// After Done is closed, ServeErr yields the loop's terminal error
// (nil for graceful shutdown via Shutdown, http.ErrServerClosed
// when the listener is closed directly).
func (r *Runtime) Done() <-chan struct{} {
	return r.done
}

// ServeErr returns the terminal error from the serve loop. Returns
// nil before Done is closed. http.ErrServerClosed is normalised to
// nil so callers treat graceful shutdown as a clean exit.
func (r *Runtime) ServeErr() error {
	select {
	case <-r.done:
		if errors.Is(r.serveErr, http.ErrServerClosed) {
			return nil
		}
		return r.serveErr
	default:
		return nil
	}
}

// Addr returns the resolved listener address (useful when
// Config.Addr uses ":0"). Empty before Start.
func (r *Runtime) Addr() string {
	if r.listener == nil {
		return ""
	}
	return r.listener.Addr().String()
}

// MetricsAddr returns the resolved metrics-listener address (useful
// when Config.MetricsAddr uses ":0"). Empty when the metrics listener
// was disabled (Config.MetricsAddr == "") OR failed to bind — both
// are valid, non-error states (P-018: a metrics-port bind failure
// degrades gracefully rather than failing Start).
func (r *Runtime) MetricsAddr() string {
	if r.metricsListener == nil {
		return ""
	}
	return r.metricsListener.Addr().String()
}

// Engine returns the Gin engine wired by Start. nil before Start.
// Exposed for tests that need to drive the engine via httptest;
// CE callers compose through internal/api directly if ever needed;
// pkg/router was DELETED 2026-08-05 (P3-8, owner ruling) — its only importer
// was its own test, and the consumer its alias comment promised never existed.
func (r *Runtime) Engine() *gin.Engine {
	return r.engine
}

// Shutdown stops the HTTP server gracefully, cancels the cleanup
// goroutine, closes the DB pool. Idempotent — subsequent calls
// return the same error as the first.
//
// The supplied context bounds the graceful-drain budget. If the
// context expires before in-flight requests complete, Shutdown
// returns the context's error.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.shutdownOnce.Do(func() {
		// Cancel cleanup first so it doesn't fight with the pool
		// close.
		if r.cleanupCancel != nil {
			r.cleanupCancel()
		}

		// A-2a: stop the heartbeat and release the single-replica lease
		// (best-effort) BEFORE closing the pool, so the row is deleted
		// while the connection is still live and a successor can acquire
		// immediately instead of waiting out the lease TTL. Release is a
		// no-op if we never held the lease (override / NOT-SERVING loser).
		if r.leaseCoordinator != nil {
			r.leaseCoordinator.Release(ctx)
		}

		// Server may have been left nil if Start was never called.
		if r.srv != nil {
			if err := r.srv.Shutdown(ctx); err != nil {
				r.shutdownErr = fmt.Errorf("runtime: server shutdown: %w", err)
			}
		}

		// Metrics server (if it was bound) shuts down best-effort. Its
		// error does not overwrite the primary shutdownErr — it is a
		// secondary, internal-only listener; a hiccup here must not
		// change the caller-visible Shutdown contract for the primary
		// server. Logged instead.
		if r.metricsSrv != nil {
			if err := r.metricsSrv.Shutdown(ctx); err != nil {
				fmt.Fprintf(r.cfg.Stderr, "identuum-idp: serve: metrics server shutdown error: %v\n", err)
			}
		}

		// Close the pool LAST. Doing it before Shutdown can cause
		// in-flight handlers to fail with confusing "pool closed"
		// errors instead of completing gracefully.
		if r.pool != nil {
			r.pool.Close()
			r.pool = nil
		}
	})
	return r.shutdownErr
}

// redactURL guarantees the operator-supplied URL does not appear in
// the returned error string. If the underlying error happens to
// embed the URL verbatim (pgx parse errors sometimes do), we
// substitute a fixed sentinel; otherwise we return the original
// error message.
func redactURL(err error, databaseURL string) error {
	if err == nil || databaseURL == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, databaseURL) {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(msg, databaseURL, "[redacted database url]"))
}

// buildDeps performs the full DB + service-layer composition the
// runtime needs. It is the procedural extraction of the prior
// runGinServe inline body — same wiring, same defaults, same
// nil-passthrough behaviour for the route surface.
//
// A database URL (Config.JWKSDBURL) is REQUIRED: the full service
// layer + full router is the only serve path. An empty URL returns a
// clean error so Start fails fast at the configuration boundary rather
// than starting a degraded server. There is no no-DB "scaffold" mode.
//
// The returned auxiliary services (replay, refresh, user-session,
// auth code, login-risk, browser-token, backchannel-logout,
// token-revocation) are surfaced so Start can wire the cleanup
// driver without leaking the entire service bundle outside this
// package.
// Serving reports whether the runtime is in the serving mode — i.e. no
// fatal startup fault has been recorded (P-018). It is an
// atomically-readable view of the serving mode and is safe to call before
// Start (returns true: no report yet). When false, the process is live
// but refusing normal traffic with 503 (NOT-SERVING-JUST-ALERTING).
func (r *Runtime) Serving() bool {
	return r.startupReport.Serving()
}

// announceStartupMode emits the P-018 ERROR-level boot diagnostics when
// the process enters NOT-SERVING mode: one line per fatal fault plus a
// summary line, written to Stderr. It never panics or exits, and is
// silent when serving. Fault reasons are secret-free by construction.
func (r *Runtime) announceStartupMode() {
	if !r.startupReport.HasFatal() {
		return
	}
	faults := r.startupReport.Faults()
	fatal := 0
	for _, f := range faults {
		if f.Severity != lifecycle.SeverityFatal {
			continue
		}
		fatal++
		fmt.Fprintf(r.cfg.Stderr,
			"identuum-idp: serve: ERROR NOT-SERVING fault [component=%s severity=%s]: %s\n",
			f.Component, f.Severity, f.Reason)
	}
	fmt.Fprintf(r.cfg.Stderr,
		"identuum-idp: serve: ERROR NOT SERVING — %d fatal startup fault(s); refusing normal traffic with 503 (GET /health reports the fault, /livez stays live)\n",
		fatal)
}

// retentionSweepers bundles the four previously-unswept expiring tables
// (P2-12: password_resets, email_verifications, organization_claims,
// mfa_pending_login_sessions) so buildDeps can hand them to the cleanup
// driver in Start without widening the return tuple four times over. Each
// field is a service.ExpiredRowSweeper — the corresponding pgx repository
// satisfies it via DeleteExpired(ctx) (int64, error).
type retentionSweepers struct {
	passwordResets     service.ExpiredRowSweeper
	emailVerifications service.ExpiredRowSweeper
	claims             service.ExpiredRowSweeper
	mfaPending         service.ExpiredRowSweeper
	audit              service.ExpiredRowSweeper
}

// serviceLogger returns the zap logger buildDeps threads into every
// internal/service Config (P3-12). It is the package logger's backing zap
// instance: real after Start's InitializeZapLogger call (which runs before
// buildDeps), still the init-seeded nop in tests and CE compositions that
// never initialize package logging — so library/test silence is preserved
// without a second logging configuration.
func serviceLogger() *zap.Logger {
	// Caller-skip recalibration (P3-12 follow-up D4): the package logger's
	// backing zap carries AddCallerSkip(1), correct for the logger package's
	// wrapper methods (Printf, ErrorContext, ...) which add one frame.
	// Services call zap DIRECTLY (s.logger.Error(...)), so without the -1
	// every service log line would attribute its caller one frame too high.
	// The wrappers' own skip is untouched — this adjusts only the copy
	// handed to service Configs.
	return logger.Error.Logger.WithOptions(zap.AddCallerSkip(-1))
}

func (r *Runtime) buildDeps(ctx context.Context, report *lifecycle.StartupReport) (
	api.OSSRouterDeps,
	*pgxpool.Pool,
	*service.ClientAssertionReplayService,
	*service.RefreshTokenService,
	*service.UserSessionService,
	*service.AuthorizationCodeService,
	*service.LoginRiskService,
	*service.BrowserSessionTokenService,
	*service.BackchannelLogoutService,
	*service.TokenRevocationService,
	repository.OIDCStateRepository,
	*retentionSweepers,
	error,
) {
	// A database URL is REQUIRED to serve. The OSS runtime no longer has
	// a no-DB "scaffold" mode: the full service layer + full router is the
	// only serve path (per docs/audit/release-readiness/oss-cli-flag-audit.md
	// and the oss-cli-simplification changelog). An empty URL is a clean
	// pre-serve configuration error surfaced through Start's error return
	// (a legitimate startup boundary) — never a panic, never a degraded
	// server that silently refuses auth.
	if r.cfg.JWKSDBURL == "" {
		return api.OSSRouterDeps{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			errors.New("runtime: no database URL configured — set IDENTUUM_IDP_DATABASE_URL to serve the IdP")
	}

	pool, err := postgres.NewPool(ctx, r.cfg.JWKSDBURL, nil)
	if err != nil {
		return api.OSSRouterDeps{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			fmt.Errorf("runtime: jwks-db pool open failed: %w", redactURL(err, r.cfg.JWKSDBURL))
	}
	// P3-5: encrypt signing_keys.private_key at rest via the SAME env-keyed
	// CryptoService posture that protects every other OSS at-rest secret.
	// FAIL-CLOSED: a missing/invalid key records a StartupReport fatal
	// (process enters NOT-SERVING per P-018), so signing keys are never
	// written or read in plaintext. public_key stays plaintext (it is public).
	// The key is read directly from the environment (IDENTUUM_IDP_ENCRYPTION_KEY
	// preferred, AUTH_SERVICE_ENCRYPTION_KEY compat) — the same 32-byte-hex
	// key the operator supplies platform-wide.
	signingKeyHex := strings.TrimSpace(os.Getenv("IDENTUUM_IDP_ENCRYPTION_KEY"))
	if signingKeyHex == "" {
		signingKeyHex = strings.TrimSpace(os.Getenv("AUTH_SERVICE_ENCRYPTION_KEY"))
	}
	var signingKeyCipher postgres.PrivateKeyCipher
	if signingKeyHex == "" {
		report.Fatal("signing-key-encryption",
			"Signing-key at-rest encryption unavailable: IDENTUUM_IDP_ENCRYPTION_KEY not set; signing keys cannot be stored or read")
	} else if cs, csErr := crypto.NewCryptoService(signingKeyHex); csErr != nil {
		report.Fatal("signing-key-encryption",
			"Signing-key at-rest encryption unavailable: IDENTUUM_IDP_ENCRYPTION_KEY invalid (must be 32-byte hex)")
	} else {
		signingKeyCipher = cs
	}

	repos := postgres.NewPgxRepositories(pool, signingKeyCipher)

	// L-2: OSS plain persistent audit log. Resolve the retention override
	// (default 30d; a non-positive value disables PRUNING only, never the
	// write), set it on the audit repo, and build the persistent
	// audit.Service. NoopService stays the fallback for cipher-free /
	// non-DB compositions (this path only runs with a live pool).
	repos.Audit.SetRetention(resolveAuditRetention(r.cfg.Getenv))
	auditSvc := service.NewPersistentAuditService(repos.Audit)

	// P3-5 boot sweep: actively re-encrypt any LEGACY plaintext-PEM signing
	// keys so a snapshot never carries forgeable private material. Idempotent
	// (already-encrypted rows are skipped); the repo logs the count.
	// Best-effort: an un-swept plaintext row still reads via passthrough and
	// is re-encrypted on next rotation, so a sweep error must not abort boot.
	if signingKeyCipher != nil {
		if kr, ok := repos.Key.(*postgres.PgxKeyRepository); ok {
			if _, sweepErr := kr.ReEncryptPlaintextKeys(ctx); sweepErr != nil {
				logger.Error.WithFields(map[string]any{"error": sweepErr.Error()}).
					Print("P3-5: signing-key re-encryption sweep failed (legacy plaintext rows remain; will re-encrypt on next rotation)")
			}

			// SIGNING-KEY-SEAL-1: make an undecryptable ACTIVE signing key a
			// loud, health-visible failure instead of a log line under a green
			// /health. If active/rotating rows exist but none are usable
			// (decryptable), record a FATAL fault so /health reports
			// NOT-SERVING with a named state and boot says so once.
			activeRows, countErr := kr.CountActiveSigningKeyRows(ctx)
			if countErr != nil {
				logger.Error.WithFields(map[string]any{"error": countErr.Error()}).
					Print("SIGNING-KEY-SEAL: could not count active signing keys; cannot evaluate seal state")
			} else if activeRows > 0 {
				usable, usableErr := kr.GetActiveSigningKeys(ctx)
				if usableErr == nil && signingKeySealFault(activeRows, len(usable)) {
					report.Fatal(signingKeySealFaultName, signingKeySealFaultDetail)
					logger.Error.WithFields(map[string]any{"active_rows": activeRows}).
						Print("SIGNING-KEY-SEAL: active signing key(s) are undecryptable under the current at-rest key — NOT SERVING (see /health)")
				}
			}
		}
	}

	jwksProvider := server.JWKSProvider(server.RepositoryJWKSProvider{Repo: repos.Key})
	keyService := service.NewKeyService(repos.Key)

	// Resolve the issuer anchor ONCE — the SINGLE source of truth for both
	// what the minters stamp (tokenSvcIssuer below reuses this) and what the
	// shared bearer verifier confines to. IDENTUUM_IDP_ISSUER unset defaults
	// to http://localhost for local dev.
	//
	// P2-5: the verifier MUST anchor to this RESOLVED value, not the raw
	// (possibly-empty) r.cfg.Issuer. VerifierOptions treats an empty
	// ExpectedIssuer/ExpectedAudience as "check DISABLED"; because every
	// minter resolves the empty issuer to http://localhost, wiring the raw
	// empty value here would mint tokens with iss/aud=http://localhost while
	// turning BOTH issuer AND audience confinement OFF — letting a token
	// minted for a downstream api_resource audience be replayed against the
	// IdP's own bearer surface. Anchoring to the resolved value keeps
	// confinement ALWAYS active in the serving binary, matched to exactly
	// what the minters stamp.
	resolvedIssuer := r.cfg.Issuer
	if resolvedIssuer == "" {
		resolvedIssuer = "http://localhost"
		// One loud operator notice (no secret): confinement is anchored to
		// localhost; a real-domain deployment MUST set the issuer.
		fmt.Fprintf(r.cfg.Stderr,
			"identuum-idp: serve: WARNING IDENTUUM_IDP_ISSUER is unset — anchoring issuer/audience confinement to %s. "+
				"On a real domain you MUST set IDENTUUM_IDP_ISSUER to the public issuer URL; otherwise self-issued "+
				"tokens and bearer issuer/audience confinement are scoped to localhost.\n", resolvedIssuer)
	}

	// Audience-confinement (FATAL-class): the shared bearer verifier
	// requires the aud claim to contain the IdP issuer. Every token
	// legitimately destined for the IdP's own surface carries aud=issuer
	// (user-session via IssueForSession; machine tokens with no requested
	// audience are stamped issuer at mint) — so this admits them and
	// rejects resource-server tokens whose aud is a downstream api_resource
	// (audience confusion). ExpectedIssuer == ExpectedAudience == the same
	// resolved anchor; no new config. Fail-closed: a non-matching aud →
	// errTokenInvalid → 401.
	tokenVerifier := mw.TokenVerifier(auth.NewRepositoryVerifier(report, repos.Key, auth.VerifierOptions{
		ExpectedIssuer:   resolvedIssuer,
		ExpectedAudience: resolvedIssuer,
	}))
	clientRepo := repository.ClientRepository(repos.Client)
	apiResourceRepo := repository.APIResourceRepository(repos.APIResource)
	scopeTemplateRepo := repository.ScopeTemplateRepository(repos.ScopeTemplate)
	clientSvc := service.NewClientService(report, repos.Client)
	apiResourceSvc := service.NewAPIResourceService(report, repos.APIResource)
	scopeTemplateSvc := service.NewScopeTemplateService(report, repos.ScopeTemplate)
	userRepo := repository.UserRepository(repos.User)
	orgRepo := repository.OrganizationRepository(repos.Organization)
	orgDomainRepo := repository.OrganizationDomainRepository(repos.OrganizationDomain)
	idpRepo := repository.IdentityProviderRepository(repos.IdentityProvider)
	userSvc := service.NewUserService(report, repos.User)
	orgSvc := service.NewOrganizationService(report, repos.Organization)
	orgDomainSvc := service.NewOrganizationDomainService(report, repos.OrganizationDomain, service.NewDNSDomainProofVerifier(service.DNSDomainProofVerifierOptions{}))
	// WithUserRepository installs the target-user tenant validation
	// hook consumed by AssignRoleToUserForActor. Without it the
	// service fails closed on assign.
	orgRoleSvc := service.NewOrgRoleService(report, repos.OrgRole, repos.APIResource).
		WithUserRepository(repos.User)
	// Per-organization DCR + SCIM protocol settings (owner
	// correction 2026-06-04 — replaces global env toggles).
	orgProtoSettingsSvc := service.NewOrganizationProtocolSettingsService(report, repos.OrganizationProtocolSettings)

	userScopeSvc := service.NewUserScopeService(report, repos.OrgRole)
	introspectionSvc := service.NewIntrospectionService(report,
		tokenVerifier.(*auth.RepositoryVerifier),
		userScopeSvc,
	)

	// Single source of truth: the minters stamp exactly the same anchor the
	// bearer verifier confines to (resolved above). No independent
	// re-resolution → no drift (P2-5).
	tokenSvcIssuer := resolvedIssuer
	tokenEndpointURL := strings.TrimRight(tokenSvcIssuer, "/") + "/api/v1/oauth/token"
	assertionValidator, assertionErr := service.NewClientAssertionValidator(service.ClientAssertionValidatorConfig{
		TokenEndpointURL: tokenEndpointURL,
	})
	if assertionErr != nil {
		pool.Close()
		return api.OSSRouterDeps{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			fmt.Errorf("runtime: assertion validator init failed: %w", assertionErr)
	}
	replaySvc := service.NewClientAssertionReplayService(report, repos.ClientAssertionReplay, service.ClientAssertionReplayServiceOptions{})
	jwksFetcher := service.NewClientJWKSFetcherService(service.ClientJWKSFetcherOptions{})
	assertionValidator = assertionValidator.
		WithReplayDetector(replaySvc).
		WithJWKSFetcher(jwksFetcher)
	oauthClientAuth := service.NewOAuthClientAuthService(report, clientSvc, apiResourceSvc).
		WithAssertionValidator(assertionValidator, clientSvc)

	serviceAccountSvc := service.NewServiceAccountService(report, repos.ServiceAccount)
	clientSvc = clientSvc.WithServiceAccountBindingValidator(serviceAccountSvc)
	saClientBundleRepo := postgres.NewPgxServiceAccountClientBundleRepository(pool)
	saClientBundleSvc := service.NewServiceAccountClientBundleService(report, serviceAccountSvc, clientSvc, saClientBundleRepo)

	sessionRepo := repository.SessionRepository(repos.Session)
	userSessionSvc := service.NewUserSessionService(report, repos.Session, service.UserSessionServiceOptions{})
	orgRoleSvc = orgRoleSvc.WithSessionRevoker(userSessionSvc)

	// MFA at-rest protection (all-tiers AES-256-GCM invariant). The TOTP
	// seed is encrypted at rest via the static-vault CryptoService keyed by
	// the operator-supplied IDENTUUM_IDP_ENCRYPTION_KEY (resolved into
	// r.cfg.EncryptionKey). FATAL-class / fail-closed: a missing or invalid
	// key records a StartupReport fatal (process enters NOT-SERVING per
	// P-018) and the MFA cipher is left nil, so the MFA write/verify paths
	// refuse rather than storing or reading a plaintext seed — never a
	// plaintext fallback, never a panic. Recovery codes are hashed (no key
	// needed). NOT OpenBao/Dynamic Vault — that is an Enterprise-tier
	// capability and would be a tier violation here.
	// Resolve the key via the in-OSS env secret provider (IDENTUUM_IDP_
	// preferred; AUTH_SERVICE_ compat) — no OpenBao/Dynamic Vault.
	mfaEnvProvider := secrets.NewEnvProvider()
	mfaEncKey, mfaKeyErr := mfaEnvProvider.GetSecret(ctx, "IDENTUUM_IDP_ENCRYPTION_KEY")
	if mfaKeyErr != nil {
		mfaEncKey, mfaKeyErr = mfaEnvProvider.GetSecret(ctx, "AUTH_SERVICE_ENCRYPTION_KEY")
	}
	var mfaCipher service.MFASecretCipher
	switch {
	case mfaKeyErr != nil:
		report.Fatal("mfa-encryption",
			"MFA secret encryption unavailable: IDENTUUM_IDP_ENCRYPTION_KEY not set; MFA enroll/verify will fail closed")
	default:
		if cryptoSvc, cryptoErr := crypto.NewCryptoService(mfaEncKey); cryptoErr != nil {
			report.Fatal("mfa-encryption",
				"MFA secret encryption unavailable: IDENTUUM_IDP_ENCRYPTION_KEY invalid (must be 32-byte hex); MFA enroll/verify will fail closed")
		} else {
			mfaCipher = cryptoSvc
		}
	}

	mfaVerifier := service.NewMFAVerifierService(report, service.EncryptedTOTPSecretResolver{Cipher: mfaCipher}, service.MFAVerifierOptions{})
	loginRiskSvc := service.NewLoginRiskService(report, repos.LoginAttempt, service.LoginRiskServiceOptions{Logger: serviceLogger()})
	localLoginSvc := service.NewLocalLoginService(report, repos.User, userSessionSvc, mfaVerifier).
		WithLoginRiskService(loginRiskSvc)

	mfaIssuer := "Identuum"
	mfaEnrollmentSvc := service.NewMFAEnrollmentService(report, service.MFAEnrollmentRepoOptions{
		Pending: repos.MFAPendingLoginSession,
		Users:   repos.User,
		Issuer:  mfaIssuer,
		Cipher:  mfaCipher,
	}, service.MFAEnrollmentServiceOptions{})

	// OIDC-provider config service (OSS basic single-provider login, Slice 2).
	// Reuses the existing IdentityProvider repository + the same env-keyed
	// CryptoService that protects MFA secrets (mfaCipher) to encrypt
	// client_secret at rest. No new repository or cipher is introduced.
	oidcProviderConfigSvc := service.NewOIDCProviderConfigService(report, idpRepo, mfaCipher)

	// OIDC discovery service (Slice 3) + login-initiation service (Slice 4).
	// Discovery fetches upstream metadata over the SSRF-guarded safehttp
	// client (default). Login initiation reuses the IdentityProvider repo,
	// the OIDCState repo, and the same env-keyed CryptoService (mfaCipher)
	// that protects MFA secrets — here to encrypt the PKCE verifier at rest.
	oidcDiscoverySvc := service.NewOIDCDiscoveryService(service.OIDCDiscoveryOptions{})
	oidcLoginSvc := service.NewOIDCLoginService(report, service.OIDCLoginServiceDeps{
		Providers: idpRepo,
		Discovery: oidcDiscoverySvc,
		States:    repos.OIDCState,
		Cipher:    mfaCipher,
	}, service.OIDCLoginServiceOptions{})
	// Callback service (Slice 5): consume state, exchange code over the same
	// SSRF-guarded safehttp client, and strictly validate the ID token against
	// the provider JWKS (reusing the discovery service's ResolveSigningKey).
	oidcCallbackSvc := service.NewOIDCCallbackService(report, service.OIDCCallbackServiceDeps{
		Providers:     idpRepo,
		Discovery:     oidcDiscoverySvc,
		States:        repos.OIDCState,
		Cipher:        mfaCipher,
		Users:         userRepo,
		Organizations: repos.Organization,
		Sessions:      userSessionSvc,
	}, service.OIDCCallbackServiceOptions{})

	csrfSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, csrfSecret); err != nil {
		pool.Close()
		return api.OSSRouterDeps{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			fmt.Errorf("runtime: csrf secret init failed: %w", err)
	}
	csrfSvc := service.NewBrowserCSRFService(report, service.BrowserCSRFServiceOptions{
		Secret: csrfSecret,
	})

	userTokenSvc := service.NewUserTokenService(report, keyService, service.UserTokenServiceOptions{
		Issuer: tokenSvcIssuer,
	})
	authCodeSvc := service.NewAuthorizationCodeService(report, repos.OAuthAuthorizationCode, service.AuthorizationCodeServiceOptions{})
	idTokenSvc := service.NewIDTokenService(report, keyService, service.IDTokenServiceOptions{
		Issuer: tokenSvcIssuer,
	})
	idTokenVerifier := service.NewIDTokenVerifier(report, repos.Key, service.IDTokenVerifierOptions{
		Issuer: tokenSvcIssuer,
	})
	consentSvc := service.NewConsentService(report, repos.OAuthConsent)
	browserTokenSvc := service.NewBrowserSessionTokenService(report, repos.BrowserSessionToken, service.BrowserSessionTokenServiceOptions{})
	cookieSvc := service.NewCookieSessionService(report, userSessionSvc, repos.User, service.CookieSessionServiceOptions{}).
		WithBrowserTokenService(browserTokenSvc).
		WithOrganizationLookup(repos.Organization)
	logoutTokenSvc := service.NewLogoutTokenService(report, keyService, service.LogoutTokenServiceOptions{
		Issuer: tokenSvcIssuer,
	})
	backchannelLogoutSvc := service.NewBackchannelLogoutService(report, logoutTokenSvc, service.BackchannelLogoutServiceOptions{}).
		WithDeliveryRepository(repos.BackchannelLogoutDelivery).
		WithDueProcessorClientLookup(clientSvc)
	backchannelDeliveryAdminSvc := service.NewBackchannelDeliveryAdminService(report,
		repos.BackchannelLogoutDelivery,
		backchannelLogoutSvc,
		clientSvc,
	)
	authorizeSvc := service.NewAuthorizeService(report, clientSvc, authCodeSvc, service.AuthorizeServiceOptions{
		Issuer: tokenSvcIssuer,
	}).
		WithAudienceLookup(apiResourceSvc).
		WithSessionLookup(repos.Session).
		WithConsentService(consentSvc).
		WithOrganizationLookup(repos.Organization)
	tokenSvc := service.NewTokenService(report, keyService, service.TokenServiceOptions{
		Issuer: tokenSvcIssuer,
	}).
		WithAudienceLookup(apiResourceSvc).
		WithServiceAccountLookup(serviceAccountSvc, clientSvc)
	tokenRevocationSvc := service.NewTokenRevocationService(report, repos.TokenRevocation)
	refreshTokenSvc := service.NewRefreshTokenService(report, repos.RefreshToken, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(tokenRevocationSvc).
		WithUserOrgLookup(repos.User)
	tokenSvc = tokenSvc.WithRefreshTokenService(refreshTokenSvc)

	var webAuthnSvc *service.WebAuthnService
	webAuthnBaseURL := tokenSvcIssuer
	if webAuthnBaseURL != "" {
		webAuthnSessionRepo := repository.NewInMemoryWebAuthnSessionRepository()
		uiPublicBaseURL := resolveUIPublicBaseURLForWebAuthn(r.cfg.Getenv, webAuthnBaseURL)
		webAuthnInst, webAuthnErr := service.NewWebAuthnService(service.WebAuthnServiceConfig{
			BaseURL:         webAuthnBaseURL,
			UIPublicBaseURL: uiPublicBaseURL,
			RPDisplayName:   "Identuum",
			UserRepo:        repos.User,
			CredRepo:        repos.WebAuthnCredential,
			SessionRepo:     webAuthnSessionRepo,
			Audit:           auditSvc,        // L-2: OSS persistent audit log
			Logger:          serviceLogger(), // P3-12: real in the serving runtime
		})
		if webAuthnErr != nil {
			fmt.Fprintln(r.cfg.Stdout, "identuum-idp: serve: webauthn skipped:", webAuthnErr)
		} else {
			webAuthnSvc = webAuthnInst
		}
	}

	// Outbound email (password-reset / verification / activation links).
	// Resolved from the runtime's own env path (IDENTUUM_IDP_SMTP_*, the
	// SMTP password via secrets.EnvProvider). When SMTP is not configured
	// the services receive the
	// honest UnconfiguredEmailNotifier: every attempted send surfaces as
	// a Warn log with an explicit "not configured" error instead of a
	// silent no-op, and the boot log states it up front. Wire responses
	// (anti-enumeration messages) are unchanged either way.
	linkBaseURL := r.cfg.UIPublicBaseURL
	if linkBaseURL == "" {
		linkBaseURL = r.cfg.Issuer
	}
	smtpNotifier, emailMode := resolveEmailNotifier(ctx, r.cfg.Getenv, linkBaseURL)
	var resetNotifier service.PasswordResetNotifier = service.UnconfiguredEmailNotifier{}
	var verifyNotifier service.EmailVerificationNotifier = service.UnconfiguredEmailNotifier{}
	var activationNotifier service.OrganizationActivationNotifier = service.UnconfiguredEmailNotifier{}
	if smtpNotifier != nil { // assign only when concrete non-nil (typed-nil-interface guard)
		resetNotifier, verifyNotifier, activationNotifier = smtpNotifier, smtpNotifier, smtpNotifier
	}
	fmt.Fprintln(r.cfg.Stdout, "identuum-idp: serve: email delivery:", emailMode)

	passwordResetSvc := service.NewPasswordResetService(service.PasswordResetServiceConfig{
		Users:    repos.User,
		Resets:   repos.PasswordReset,
		Sessions: repos.Session,
		Notifier: resetNotifier,
		// HumanFacingBaseURL is the UI origin the reset link points at.
		HumanFacingBaseURL: linkBaseURL,
		Audit:              auditSvc,        // L-2
		Logger:             serviceLogger(), // P3-12
	}).WithRefreshTokenRevoker(refreshTokenSvc)
	emailVerificationSvc := service.NewEmailVerificationService(
		repos.User,
		repos.EmailVerification,
		verifyNotifier,
		nil,
		service.EmailVerificationServiceOptions{Logger: serviceLogger()}, // P3-12
	)
	orgActivationSvc := service.NewOrganizationActivationService(service.OrganizationActivationServiceConfig{
		Users:     repos.User.(*postgres.PgxUserRepository),
		Orgs:      repos.Organization,
		OrgsAdmin: repos.Organization.(*postgres.PgxOrganizationRepository),
		Notifier:  activationNotifier,
		Audit:     auditSvc,        // L-2
		Logger:    serviceLogger(), // P3-12
	})
	claimSvc := service.NewClaimService(service.ClaimServiceConfig{
		Claims:    repos.Claim,
		Orgs:      repos.Organization,
		OrgsAdmin: repos.Organization.(*postgres.PgxOrganizationRepository),
		Users:     repos.User,
		Exists:    repos.User,
		Logger:    serviceLogger(), // P3-12 follow-up: zero log sites today, threaded so the derived Logger-field pin holds uniformly
		Audit:     auditSvc,        // L-2
	})

	fmt.Fprintln(r.cfg.Stdout,
		"identuum-idp: serve: db pool ready; JWKS, /api/v1/keys, /api/v1/clients, /api/v1/api-resources, /api/v1/scope-templates, /api/v1/users, /api/v1/organizations (+ org domains), /api/v1/me/roles + RBAC org/user role routes + password-reset / verify-email / activation / claim lifecycle routes wired with OSS service layer")
	fmt.Fprintln(r.cfg.Stdout,
		"identuum-idp: serve: organization_protocol_settings DB-backed (per-org DCR + SCIM toggles enforced)")

	// Operator hardening flag: IDENTUUM_IDP_PUBLIC_HIDE_IDP_EMAIL_DOMAINS omits
	// email_domains from the PUBLIC organization-lookup projection. Unset,
	// empty, or malformed ⇒ false (exposed — current behavior, zero-change
	// default; P-018: a bad value degrades to the safe default). Gates ONLY the
	// public lookup — the authenticated admin identity-provider API is
	// unaffected.
	hidePublicIDPEmailDomains := resolveHidePublicIDPEmailDomains(r.cfg.Getenv)

	deps := api.OSSRouterDeps{
		Version:                           r.cfg.Version,
		DiscoveryConfig:                   server.OIDCDiscoveryConfig{Issuer: r.cfg.Issuer},
		JWKSProvider:                      jwksProvider,
		KeyService:                        keyService,
		TokenVerifier:                     tokenVerifier,
		ClientRepo:                        clientRepo,
		APIResourceRepo:                   apiResourceRepo,
		ScopeTemplateRepo:                 scopeTemplateRepo,
		ClientService:                     clientSvc,
		APIResourceService:                apiResourceSvc,
		ScopeTemplateService:              scopeTemplateSvc,
		UserRepo:                          userRepo,
		OrganizationRepo:                  orgRepo,
		OrganizationDomainRepo:            orgDomainRepo,
		IdentityProviderRepo:              idpRepo,
		UserService:                       userSvc,
		OrganizationService:               orgSvc,
		OrganizationDomainService:         orgDomainSvc,
		OrgRoleService:                    orgRoleSvc,
		ServiceAccountService:             serviceAccountSvc,
		ServiceAccountClientBundleService: saClientBundleSvc,
		LocalLogin:                        localLoginSvc,
		MFAEnrollment:                     mfaEnrollmentSvc,
		UserSessionService:                userSessionSvc,
		// SessionRevoker is the seam consumed by the /oauth/revoke
		// fan-out path: when a verified token's `sub` is a UUID,
		// the handler invokes RevokeUserSessions for that user with
		// reason="oauth_token_revoked". UserSessionService already
		// satisfies the SessionRevoker interface (pinned by a
		// compile-time _ = SessionRevoker((*UserSessionService)(nil))
		// assertion in user_session_service.go), so plugging it in
		// here is the only wiring step the runtime owes the route.
		// Deployments without a session repo still fall through to
		// NoopSessionRevoker via the handler-level default.
		SessionRevoker:                      userSessionSvc,
		UserToken:                           userTokenSvc,
		UserLookup:                          userRepo,
		AuthorizationCodeService:            authCodeSvc,
		SessionLookup:                       sessionRepo,
		SessionRepo:                         sessionRepo,
		AuthorizeService:                    authorizeSvc,
		IDTokenService:                      idTokenSvc,
		CookieSession:                       cookieSvc,
		ConsentService:                      consentSvc,
		IDTokenVerifier:                     idTokenVerifier,
		CSRF:                                csrfSvc,
		FrontchannelLogoutEnabled:           true,
		HidePublicIDPEmailDomains:           hidePublicIDPEmailDomains,
		BrowserTokens:                       browserTokenSvc,
		BackchannelLogoutService:            backchannelLogoutSvc,
		BackchannelDeliveryAdminService:     backchannelDeliveryAdminSvc,
		IntrospectionService:                introspectionSvc,
		OAuthClientAuth:                     oauthClientAuth,
		TokenService:                        tokenSvc,
		TokenRevocationService:              tokenRevocationSvc,
		RefreshTokenService:                 refreshTokenSvc,
		WebAuthnService:                     webAuthnSvc,
		PasswordResetService:                passwordResetSvc,
		EmailVerificationService:            emailVerificationSvc,
		OrganizationActivationService:       orgActivationSvc,
		ClaimService:                        claimSvc,
		OrganizationProtocolSettingsService: orgProtoSettingsSvc,
		OIDCProviderConfigService:           oidcProviderConfigSvc,
		OIDCLoginService:                    oidcLoginSvc,
		OIDCCallbackService:                 oidcCallbackSvc,
		CORSAllowedOrigins:                  r.cfg.CORSAllowedOrigins,
		TrustedProxies:                      r.cfg.TrustedProxies,
		// Per-class request-rate limits (login/register/token/introspection/
		// password-reset). Sourced from the runtime's own env path (NOT the
		// inert appconfig package), with safe defaults, so the shipped IdP
		// actually rate-limits instead of shipping a zero-value no-op.
		RateLimitConfig: resolveRateLimitConfig(r.cfg.Getenv),
	}

	// Appliance first-run setup foundation. The service is wired
	// only when the DB pool is open (we need a real repository for
	// the singleton system_setup_state row). The route registration
	// is gated on deps.SetupService != nil — see api/router.go.
	setupRepo := postgres.NewPgxSetupStateRepository(pool)
	// Wire the loud-warning sink to runtime stderr. The Service uses it
	// only when the post-completion DeleteTokenFile sweep fails — the
	// DB has already been flipped to 'setup_complete' at that point.
	stderr := r.cfg.Stderr
	setupSvc := setup.New(setup.Deps{
		Repo:            setupRepo,
		OrgService:      orgSvc,
		KeyService:      keyService,
		OrgRepo:         orgRepo,
		UserRepo:        userRepo,
		Issuer:          r.cfg.Issuer,
		UIPublicBaseURL: r.cfg.UIPublicBaseURL,
		Logf: func(format string, args ...any) {
			if stderr == nil {
				return
			}
			fmt.Fprintf(stderr, "identuum-idp: "+format+"\n", args...)
		},
	})
	deps.SetupService = setupSvc
	deps.SetupDataDir = r.cfg.DataDir
	// L-2: wire the persistent audit log so handler-side audit.Record
	// emissions land in audit_events instead of NoopService's discard.
	deps.Audit = auditSvc
	// L-2 read half: the pgx audit repo backs GET /api/v1/audit/events.
	deps.AuditReader = repos.Audit

	// P2-12: the four previously-unswept expiring tables, handed to the
	// cleanup driver in Start. Each repo satisfies service.ExpiredRowSweeper.
	sweepers := &retentionSweepers{
		passwordResets:     repos.PasswordReset,
		emailVerifications: repos.EmailVerification,
		claims:             repos.Claim,
		mfaPending:         repos.MFAPendingLoginSession,
		audit:              repos.Audit,
	}

	return deps, pool, replaySvc, refreshTokenSvc, userSessionSvc,
		authCodeSvc, loginRiskSvc, browserTokenSvc,
		backchannelLogoutSvc, tokenRevocationSvc, repos.OIDCState, sweepers, nil
}
