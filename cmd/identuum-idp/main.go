// Command identuum-idp is the OSS build of the Identuum identity
// provider entrypoint.
//
// Usage shape (public-release CLI — see
// docs/audit/release-readiness/oss-cli-flag-audit.md):
//
//	identuum-idp                     # serve the full OSS IdP (default action)
//	identuum-idp migrate [url]       # apply embedded migrations, then a sanity check
//	identuum-idp bootstrap [url]     # one-shot: ensure a signing key + create site_admin
//	identuum-idp recover-site-admin [url]  # one-shot: reset the site_admin password + MFA
//	identuum-idp show-setup-code <data-dir># print the appliance setup code while setup_required
//	identuum-idp doctor [url]        # READ-ONLY diagnosis with named states (exit 0 healthy)
//	identuum-idp factory-reset --i-understand-this-destroys-all-data [url]
//	                                 # DESTROY all data; refused without the flag
//	identuum-idp --version           # print the build version and exit
//
// One-shot subcommands taking [url] fall back to IDENTUUM_IDP_DATABASE_URL,
// then IDENTUUM_IDP_OSS_DB, when the argument is absent (DSN-DEFAULT-1) — so
// on a container that knows its own database each is one flag-less
// `docker exec`. The URL is never printed.
//
// The default action (no subcommand) starts the full OSS IdP: the Gin
// route surface, the OSS service layer, OAuth/OIDC, local auth, MFA,
// WebAuthn, DCR, the Authorization Server primitives, and the
// background revocation-cleanup loop. The serving configuration is read
// from the environment so the common case needs no flags:
//
//	IDENTUUM_IDP_DATABASE_URL   Postgres URL (REQUIRED to serve; never printed)
//	IDENTUUM_IDP_ISSUER         public issuer base URL advertised in discovery
//	IDENTUUM_IDP_LISTEN         listen address (default 0.0.0.0:7113)
//	IDENTUUM_IDP_ENCRYPTION_KEY at-rest AES key (read by the runtime; see the MFA-key audit)
//	IDENTUUM_IDP_DATA_DIR       persistent data dir for the setup foundation
//	IDENTUUM_IDP_UI_PUBLIC_BASE_URL  optional UI base URL used to compose the setup URL
//
// When no database URL is configured, the binary exits non-zero with a
// clear message naming the missing variable rather than starting a
// degraded server. Subcommands take the Postgres URL as a positional
// argument and read their secrets from the environment; no operator-
// supplied URL or secret is ever echoed, even on failure.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/buildinfo"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	pkgruntime "github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// buildVersion is STAMPED at release build time via
//
//	go build -ldflags "-X main.buildVersion=<semver>"
//
// (deployment/Dockerfile.local ARG VERSION; the publish workflow passes the
// dispatched tag with its leading v stripped; `make build` stamps from
// `git describe`). The dev fallback can never match a release tag, so the
// publish workflow's canonical binary-vs-tag gate refuses any build where the
// stamping plumbing broke — the same protection the old hand-bumped const
// gave, without a source edit per release (THE-V032-ALL-GREEN Order C).
var buildVersion = "dev"

// version is reported by --version. It is the build-time identifier for
// the OSS IdP entrypoint.
var version = "identuum-idp-oss " + buildVersion

// errURLRedacted replaces every operator-supplied database URL in
// error paths. The binary never prints a URL even on failure; see
// redactURL for the redaction guarantee.
var errURLRedacted = errors.New("[redacted database url]")

// run is the testable entrypoint. main() delegates to run() so that
// tests can capture stdout/stderr without touching the real os.Stdout.
//
// Return value matches process exit code semantics: 0 = success,
// non-zero = error.
func run(args []string, stdout, stderr io.Writer) int {
	// Subcommand dispatch: the first non-flag argument selects an
	// operator one-shot. Serving is the default action (no subcommand).
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub := args[0]
		rest := args[1:]
		switch sub {
		case "migrate":
			url, ok := requirePositionalURL(sub, rest, stderr)
			if !ok {
				return 2
			}
			return runMigrate(context.Background(), url, stdout, stderr)
		case "bootstrap":
			url, ok := requirePositionalURL(sub, rest, stderr)
			if !ok {
				return 2
			}
			return runBootstrap(context.Background(), url, stdout, stderr)
		case "recover-site-admin":
			url, ok := requirePositionalURL(sub, rest, stderr)
			if !ok {
				return 2
			}
			return runRecoverSiteAdmin(context.Background(), url, stdout, stderr)
		case "show-setup-code":
			return dispatchShowSetupCode(rest, stdout, stderr)
		case "doctor":
			return dispatchDoctor(context.Background(), rest, stdout, stderr)
		case "factory-reset":
			return dispatchFactoryReset(context.Background(), rest, stdout, stderr)
		case "rotate-encryption-key":
			return dispatchRotateEncryptionKey(context.Background(), rest, stdout, stderr)
		case "appliance":
			// The container entrypoint (P2-19c): prepare, migrate, drop
			// privileges, serve — in ONE process, because a distroless
			// image has no shell to sequence it.
			return runAppliance(context.Background(), rest, stdout, stderr)
		case "version":
			fmt.Fprintln(stdout, version+" (commit "+buildinfo.Commit+")")
			return 0
		case "help", "-h", "--help":
			printUsage(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "identuum-idp: unknown subcommand %q\n", sub)
			printUsage(stderr)
			return 2
		}
	}

	// Default action: serve the full OSS IdP. Only serve-related flags
	// are accepted here; every flag is env-defaulted so the common case
	// needs none.
	fs := flag.NewFlagSet("identuum-idp", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		showVersion               bool
		listenAddr                string
		issuer                    string
		databaseURL               string
		revocationCleanupInterval time.Duration
		metricsAddr               string
	)
	fs.BoolVar(&showVersion, "version", false, "Print the OSS IdP version and exit.")
	fs.StringVar(&listenAddr, "listen", "", "Listen address (default $IDENTUUM_IDP_LISTEN, then 0.0.0.0:7113).")
	fs.StringVar(&issuer, "issuer", "", "Issuer base URL advertised in OIDC discovery (default $IDENTUUM_IDP_ISSUER).")
	fs.StringVar(&databaseURL, "database-url", "", "Postgres URL (default $IDENTUUM_IDP_DATABASE_URL). REQUIRED to serve. Never printed, even on failure.")
	fs.DurationVar(&revocationCleanupInterval, "revocation-cleanup-interval", time.Hour, "Interval at which expired rows are pruned from oauth_token_revocations. Set to 0 to disable. Default 1h.")
	fs.StringVar(&metricsAddr, "metrics-addr", "", "Prometheus /metrics listen address — SEPARATE from --listen, internal-only, unauthenticated (default $IDENTUUM_IDP_METRICS_ADDR, then 127.0.0.1:9090 = LOOPBACK; labels carry org/provider IDs, so set a routable address e.g. 0.0.0.0:9090 only to deliberately expose it). Set to \"-\" to disable the metrics listener entirely.")

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already wrote the error message to stderr.
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "identuum-idp: unexpected positional arguments: %v\n", fs.Args())
		printUsage(stderr)
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	// Resolve serving configuration: explicit flag wins, else env.
	if databaseURL == "" {
		databaseURL = os.Getenv("IDENTUUM_IDP_DATABASE_URL")
	}
	if databaseURL == "" {
		fmt.Fprintln(stderr, "identuum-idp: no database URL configured — set IDENTUUM_IDP_DATABASE_URL (or pass --database-url) to serve the IdP")
		return 2
	}
	if listenAddr == "" {
		listenAddr = os.Getenv("IDENTUUM_IDP_LISTEN")
	}
	if listenAddr == "" {
		listenAddr = "0.0.0.0:7113"
	}
	if issuer == "" {
		issuer = os.Getenv("IDENTUUM_IDP_ISSUER")
	}
	metricsAddr = resolveMetricsAddr(metricsAddr, os.Getenv("IDENTUUM_IDP_METRICS_ADDR"))

	return runServe(listenAddr, issuer, databaseURL, revocationCleanupInterval, metricsAddr, stdout, stderr)
}

// requirePositionalURL extracts the Postgres-URL positional argument for an
// operator subcommand, falling back to the environment when none is given —
// the SAME precedence the appliance uses (IDENTUUM_IDP_DATABASE_URL, then
// IDENTUUM_IDP_OSS_DB). The fallback exists for `docker exec` against the
// distroless runtime image: there is no shell in that image to expand the
// container's own env into a positional, and the container already knows its
// database. The URL is never echoed.
func requirePositionalURL(sub string, rest []string, stderr io.Writer) (string, bool) {
	args := make([]string, 0, len(rest))
	for _, a := range rest {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(stderr, "identuum-idp: %s: unexpected flag %q (usage: identuum-idp %s [database-url])\n", sub, a, sub)
			return "", false
		}
		args = append(args, a)
	}
	switch {
	case len(args) == 1 && args[0] != "":
		return args[0], true
	case len(args) == 0:
		for _, env := range []string{"IDENTUUM_IDP_DATABASE_URL", "IDENTUUM_IDP_OSS_DB"} {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				return v, true
			}
		}
	}
	fmt.Fprintf(stderr, "identuum-idp: %s requires a <database-url> argument, or "+
		"IDENTUUM_IDP_DATABASE_URL / IDENTUUM_IDP_OSS_DB in the environment (URL is never printed)\n", sub)
	return "", false
}

// dispatchShowSetupCode parses the show-setup-code subcommand:
//
//	identuum-idp show-setup-code [--database-url <url>] <data-dir>
//
// FLAGS COME FIRST. Go's flag package stops parsing at the first
// non-flag argument, so the documented-but-wrong
// `show-setup-code <data-dir> --database-url <url>` left the flag and
// its value sitting in fs.Args() — NArg()==3 — and the command died
// with "requires exactly one <data-dir> argument" (THE-MANUAL-TARGETS,
// measured live by the operator).
//
// The data dir is the single positional argument; --database-url
// overrides IDENTUUM_IDP_DATABASE_URL (and the compose-shaped
// IDENTUUM_IDP_OSS_DB fallback). Behavior is otherwise identical
// to the prior --show-setup-code flag: it prints the appliance setup
// code only while the database reports setup_required, and the URL is
// never echoed.
func dispatchShowSetupCode(rest []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("identuum-idp show-setup-code", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var dbURLOverride string
	fs.StringVar(&dbURLOverride, "database-url", "", "Optional Postgres URL override (default $IDENTUUM_IDP_DATABASE_URL). Never echoed.")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if fs.NArg() != 1 || fs.Arg(0) == "" {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code requires exactly one <data-dir> argument")
		return 2
	}
	return showSetupCodeCommand(context.Background(), fs.Arg(0), dbURLOverride, os.Getenv, stdout, stderr)
}

// printUsage prints the minimal command summary.
func printUsage(w io.Writer) {
	fmt.Fprintln(w, "identuum-idp — Identuum OSS identity provider")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Default action (no subcommand): serve the full OSS IdP.")
	fmt.Fprintln(w, "  Configuration is read from the environment:")
	fmt.Fprintln(w, "    IDENTUUM_IDP_DATABASE_URL   Postgres URL (REQUIRED to serve; never printed)")
	fmt.Fprintln(w, "    IDENTUUM_IDP_ISSUER         public issuer base URL")
	fmt.Fprintln(w, "    IDENTUUM_IDP_LISTEN         listen address (default 0.0.0.0:7113)")
	fmt.Fprintln(w, "    IDENTUUM_IDP_METRICS_ADDR   Prometheus /metrics listen address, SEPARATE listener,")
	fmt.Fprintln(w, "                                internal-only + unauthenticated (default 127.0.0.1:9090 =")
	fmt.Fprintln(w, "                                LOOPBACK; labels carry org/provider IDs — set a routable")
	fmt.Fprintln(w, "                                address only to expose it; \"-\" disables it)")
	fmt.Fprintln(w, "    IDENTUUM_IDP_ENCRYPTION_KEY at-rest AES key")
	fmt.Fprintln(w, "  Optional overrides: --listen, --issuer, --database-url, --revocation-cleanup-interval, --metrics-addr")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Operator subcommands (one-shot; the URL/secret is never printed):")
	fmt.Fprintln(w, "  migrate <database-url>             apply embedded migrations, then a sanity check")
	fmt.Fprintln(w, "  bootstrap <database-url>           ensure a signing key + create site_admin")
	fmt.Fprintln(w, "                                     (reads IDENTUUM_IDP_BOOTSTRAP_PASSWORD)")
	fmt.Fprintln(w, "  recover-site-admin <database-url>  reset the site_admin password + MFA")
	fmt.Fprintln(w, "                                     (reads IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD)")
	fmt.Fprintln(w, "  show-setup-code [--database-url <url>] <data-dir>")
	fmt.Fprintln(w, "                                     print the setup code while setup_required")
	fmt.Fprintln(w, "                                     (flags BEFORE the positional — Go's parser")
	fmt.Fprintln(w, "                                     stops at the first non-flag argument)")
	fmt.Fprintln(w, "  doctor [database-url]              READ-ONLY diagnosis: named states for version,")
	fmt.Fprintln(w, "                                     db, at-rest key, setup, signing-key seal;")
	fmt.Fprintln(w, "                                     exit 0 healthy, non-zero names the failing state")
	fmt.Fprintln(w, "  factory-reset --i-understand-this-destroys-all-data [database-url]")
	fmt.Fprintln(w, "                                     DESTROY all data and return the database to")
	fmt.Fprintln(w, "                                     factory state (refused without the flag)")
	fmt.Fprintln(w, "  rotate-encryption-key [database-url]")
	fmt.Fprintln(w, "                                     re-encrypt every at-rest secret from")
	fmt.Fprintln(w, "                                     $IDENTUUM_IDP_OLD_ENCRYPTION_KEY to")
	fmt.Fprintln(w, "                                     $IDENTUUM_IDP_ENCRYPTION_KEY in one")
	fmt.Fprintln(w, "                                     transaction; OFFLINE ONLY (refuses while")
	fmt.Fprintln(w, "                                     a process holds the instance lease)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Subcommands taking [database-url] fall back to IDENTUUM_IDP_DATABASE_URL,")
	fmt.Fprintln(w, "  then IDENTUUM_IDP_OSS_DB, when the argument is absent (the URL is never printed).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  --version                          print the build version and exit")
}

// runMigrate opens a stdlib DB, applies pending migrations, then hands
// off to runDBCheck which opens a pool and runs a sentinel query.
// Errors are redacted to prevent the URL from appearing in stderr.
func runMigrate(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	db, err := postgres.OpenStdlibDB(databaseURL)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: migrate: open stdlib db failed:", redactURL(err, databaseURL))
		return 1
	}
	results, err := postgres.RunMigrations(ctx, db)
	closeErr := db.Close()
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: migrate: run migrations failed:", redactURL(err, databaseURL))
		return 1
	}
	if closeErr != nil {
		fmt.Fprintln(stderr, "identuum-idp: migrate: close stdlib db failed:", redactURL(closeErr, databaseURL))
		return 1
	}

	applied := 0
	for _, r := range results {
		if r.Applied {
			applied++
		}
	}
	fmt.Fprintf(stdout, "identuum-idp: migrate: applied %d migration(s) of %d embedded\n", applied, len(results))

	return runDBCheck(ctx, databaseURL, stdout, stderr)
}

// parseCORSAllowedOrigins parses the comma-separated
// IDENTUUM_IDP_CORS_ALLOWED_ORIGINS value into an exact-match origin
// allowlist. Whitespace around each entry is trimmed and empty entries
// are dropped, so "" (unset) yields a nil slice — deny all cross-origin.
// A literal "*" is preserved here but ignored by the CORS middleware,
// which never emits a wildcard origin.
func parseCORSAllowedOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var origins []string
	for _, part := range strings.Split(raw, ",") {
		if o := strings.TrimSpace(part); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

// parseTrustedProxies parses the comma-separated IDENTUUM_IDP_TRUSTED_PROXIES
// value into a list of trusted reverse-proxy addresses/CIDRs for gin's
// SetTrustedProxies. Whitespace is trimmed and empty entries dropped, so ""
// (unset) yields a nil slice — trust NO proxy, meaning c.ClientIP() is the
// direct peer and a forged X-Forwarded-For cannot spoof rate limiting or
// audit/security-event attribution. Operators fronting the app with a reverse
// proxy MUST set this (e.g. "10.0.0.0/8,192.168.0.0/16") or client IPs will be
// the proxy's. Malformed entries are rejected downstream by SetTrustedProxies
// (NewOSSEngine fails closed to trust-none and records a P-018 fault).
func parseTrustedProxies(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var proxies []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			proxies = append(proxies, p)
		}
	}
	return proxies
}

// defaultMetricsAddr binds the Prometheus /metrics listener to LOOPBACK by
// default (P2-4). The exported metric labels carry tenant-identifying values —
// `org_id` (identuum_idp_policy_violation_total) and OIDC `provider_id` /
// `provider_type` (identuum_idp_oidc_upstream_* / _flow_*) — so an off-box,
// unauthenticated scrape would leak the organization + identity-provider
// inventory. Exposing the endpoint is therefore an explicit operator decision,
// not a default: set --metrics-addr / IDENTUUM_IDP_METRICS_ADDR to a routable
// address (e.g. 0.0.0.0:9090). The listener is never authenticated, so an
// operator who exposes it should also restrict it at the network layer.
const defaultMetricsAddr = "127.0.0.1:9090"

// resolveMetricsAddr applies the metrics-listener address precedence:
// the --metrics-addr flag wins, else $IDENTUUM_IDP_METRICS_ADDR, else the
// loopback default (defaultMetricsAddr). The "-" sentinel (from whichever
// source wins) resolves to "" — the runtime then binds NO metrics listener at
// all. Kept as a pure function so the default + precedence + disable semantics
// are unit-testable without starting a server.
func resolveMetricsAddr(flagVal, envVal string) string {
	addr := flagVal
	if addr == "" {
		addr = envVal
	}
	if addr == "" {
		addr = defaultMetricsAddr
	}
	if addr == "-" {
		return ""
	}
	return addr
}

// runServe starts the full OSS IdP via the public pkg/runtime seam. It
// builds a runtime.Config from the resolved serving configuration,
// starts the runtime, blocks on either SIGINT/SIGTERM or the serve loop
// terminating, then drives a 5-second graceful shutdown. The runtime
// owns the DB pool, service-layer construction, the jti / refresh-token
// cleanup goroutine, and the listener lifecycle.
//
// metricsAddr binds the SEPARATE, internal-only /metrics listener
// (empty disables it entirely). It is never the same listener as addr
// — see internal/runtime.Runtime.startMetricsListener.
//
// Migrations are NOT run by the runtime — operators run
// `identuum-idp migrate <url>` first. The database URL is never printed.
func runServe(addr, issuer, databaseURL string, revocationCleanupInterval time.Duration, metricsAddr string, stdout, stderr io.Writer) int {
	rt, err := pkgruntime.New(pkgruntime.Config{
		Addr:                      addr,
		MetricsAddr:               metricsAddr,
		Issuer:                    issuer,
		JWKSDBURL:                 databaseURL,
		RevocationCleanupInterval: revocationCleanupInterval,
		Version:                   version,
		Stdout:                    stdout,
		Stderr:                    stderr,
		// Deny-by-default CORS: an unset/empty env var yields an empty
		// allowlist, so no cross-origin request is granted CORS access.
		CORSAllowedOrigins: parseCORSAllowedOrigins(os.Getenv("IDENTUUM_IDP_CORS_ALLOWED_ORIGINS")),
		// Trust NO proxy by default: an unset env var yields an empty list, so
		// c.ClientIP() is the direct peer and X-Forwarded-For is ignored.
		// Operators behind a reverse proxy MUST set this to the proxy CIDRs.
		TrustedProxies: parseTrustedProxies(os.Getenv("IDENTUUM_IDP_TRUSTED_PROXIES")),
	})
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: serve:", err)
		return 1
	}

	if err := rt.Start(context.Background()); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: serve:", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Fprintf(stdout, "identuum-idp: serve: received %s, shutting down\n", sig)
	case <-rt.Done():
		signal.Stop(sigCh)
		if err := rt.ServeErr(); err != nil {
			fmt.Fprintln(stderr, "identuum-idp: serve: server error:", err)
			return 1
		}
		return 0
	}

	signal.Stop(sigCh)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: serve: shutdown error:", err)
		return 1
	}
	return 0
}

// runDBCheck opens a pgxpool, constructs the OSS repository factory,
// runs a safe sentinel query (SELECT current_database()), and exits.
// Errors are redacted to prevent the URL from appearing in stderr.
func runDBCheck(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: db-check: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()

	// Construct the repository factory. We do not call any repository
	// methods yet — the construction itself proves the wiring compiles
	// and that the pool satisfies the DBTX interface. db-check never
	// creates or reads signing keys, so it passes a nil key cipher (the
	// key repository is fail-closed: a nil cipher can never write plaintext)
	// — this keeps the connectivity diagnostic runnable without the at-rest
	// encryption key configured.
	repos := postgres.NewPgxRepositories(pool, nil)
	if repos == nil || repos.User == nil {
		fmt.Fprintln(stderr, "identuum-idp: db-check: repository factory returned nil")
		return 1
	}

	// Safe sentinel query — current_database() returns the database
	// name. It is operator-supplied via the URL but is NOT a credential.
	var dbName string
	if err := pool.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: db-check: sentinel query failed:", redactURL(err, databaseURL))
		return 1
	}

	fmt.Fprintf(stdout, "identuum-idp: migrate: db sanity ok (database=%q, repositories=%d)\n", dbName, repositoryFieldCount())
	return 0
}

// repositoryFieldCount is the number of fields on postgres.Repositories.
// It is hard-coded rather than reflected because (a) it's small, (b) it
// matches the documented OSS aggregate cardinality, and (c) it
// surfaces silently if the aggregate is renumbered.
func repositoryFieldCount() int { return 19 }

// redactURL guarantees the operator-supplied URL does not appear in
// the returned error string. The verbatim URL is replaced with a
// fixed sentinel; in addition, when the URL is parseable as a standard
// `postgres://user:dev-user-not-a-secret@host/db` string, the individual user, password,
// and host components are also redacted so that pgx error messages
// (which decompose the URL into a `user=...` form before reporting a
// connection failure) do not leak credentials. Returns the original
// error unchanged when nothing in the message matches.
func redactURL(err error, databaseURL string) error {
	if err == nil || databaseURL == "" {
		return err
	}
	msg := err.Error()
	original := msg
	if containsSubstring(msg, databaseURL) {
		msg = replaceSubstring(msg, databaseURL, "[redacted database url]")
	}
	if u, parseErr := neturl.Parse(databaseURL); parseErr == nil {
		if u.User != nil {
			if user := u.User.Username(); user != "" {
				msg = replaceSubstring(msg, user, "[redacted]")
			}
			if pass, ok := u.User.Password(); ok && pass != "" {
				msg = replaceSubstring(msg, pass, "[redacted]")
			}
		}
		if host := u.Hostname(); host != "" {
			msg = replaceSubstring(msg, host, "[redacted]")
		}
	}
	if msg == original {
		return err
	}
	return fmt.Errorf("%s", msg)
}

// containsSubstring is a stdlib-free substring check kept inline so
// the redaction path has zero dependencies that could pull
// system-default I/O into the error path.
func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// replaceSubstring rebuilds haystack with every occurrence of needle
// replaced by replacement. Kept inline for the same reason as
// containsSubstring.
func replaceSubstring(haystack, needle, replacement string) string {
	if needle == "" {
		return haystack
	}
	var out []byte
	for i := 0; i < len(haystack); {
		if i+len(needle) <= len(haystack) && haystack[i:i+len(needle)] == needle {
			out = append(out, replacement...)
			i += len(needle)
			continue
		}
		out = append(out, haystack[i])
		i++
	}
	return string(out)
}

// Reference errURLRedacted so linters don't strip the documented
// sentinel. The constant exists for documentation of the redaction
// guarantee at the package level.
var _ = errURLRedacted

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
