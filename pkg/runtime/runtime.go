// Package runtime is the public composition seam of identuum-idp-oss: it
// builds and runs the OSS IdP runtime in the caller's process — open the
// database, wire the services, mount the route surface, serve, drain.
//
// OSS-SEAM-1 (owner ruling w, 2026-10-08): a narrow facade over the private
// runtime (internal/runtime), for a trusted caller that links it statically
// (identuum-idp-ce). It adds no behaviour: New maps Options field by field to
// the private configuration, and Start and Shutdown delegate to the existing
// lifecycle. The caller owns the process, its signals and the migration
// order: Start does not migrate (see pkg/migrations), and the schema must be
// at migrations.Current() before Start.
//
// What this package does NOT expose, on purpose: the HTTP engine and route
// table, the database pool, repositories, services and keys. The runtime
// binds its own listener on Options.Addr.
//
// Compatibility (docs/PUBLIC-API.md): patch releases keep source
// compatibility and behaviour; while the module is v0 a breaking change needs
// an announced minor release after one minor line of deprecation. The
// exported API is pinned by internal/apigolden.
//
// Security: Options.DatabaseURL is never printed; the private runtime scrubs
// it from errors. This package carries no key, license or secret of its own,
// and identuum-idp-oss never imports identuum-idp-ce.
package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"slices"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	internalruntime "github.com/identuum/identuum-idp-oss/internal/runtime"
	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

// Options configures a Runtime. Each field maps to exactly one field of the
// private configuration; the zero value of a field means the runtime's own
// default, as documented on the field.
type Options struct {
	// Addr is the address the runtime listens on, e.g. ":7113" or
	// "127.0.0.1:0". Required.
	Addr string
	// Issuer is the OpenID issuer URL the runtime advertises.
	Issuer string
	// DatabaseURL is the PostgreSQL URL. Never printed or logged.
	DatabaseURL string
	// RevocationCleanupInterval is the period of the expiry and retention
	// sweeps; zero means the runtime's default.
	RevocationCleanupInterval time.Duration
	// Version is the build string /health and /system/info report; empty
	// means "identuum-idp-oss (unknown version)".
	Version string
	// Stdout and Stderr receive the runtime's banner and logs; nil discards.
	Stdout, Stderr io.Writer
	// Getenv reads the IDENTUUM_IDP_* settings; nil means os.Getenv.
	Getenv func(string) string
	// DataDir holds the runtime's on-disk state (the at-rest key, the setup
	// state); empty means IDENTUUM_IDP_DATA_DIR, then the default directory.
	DataDir string
	// UIPublicBaseURL is the console's browser origin; empty means
	// IDENTUUM_IDP_UI_PUBLIC_BASE_URL.
	UIPublicBaseURL string
	// UIStaticDir serves a console export from disk instead of the embedded
	// one; empty means IDENTUUM_IDP_UI_DIR, then the embedded export.
	UIStaticDir string
	// MetricsAddr is the separate metrics listener; empty means none.
	MetricsAddr string
	// CORSAllowedOrigins and TrustedProxies are copied, never retained.
	CORSAllowedOrigins []string
	TrustedProxies     []string
	// Restrictions are deny-only extension restrictions on the operations
	// pkg/extension names; nil or empty runs OSS as it is. Copied.
	Restrictions []extension.Restriction
}

// Lifecycle is the consumer-facing view of a running Runtime.
type Lifecycle interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Done() <-chan struct{}
	ServeErr() error
}

// Runtime is a privately backed OSS runtime. It is single-use: after
// Shutdown, construct a new one with New.
type Runtime struct {
	rt *internalruntime.Runtime
}

var _ Lifecycle = (*Runtime)(nil)

// New validates opts and returns a Runtime that has not started. It touches
// no database, listener or file.
func New(opts Options) (*Runtime, error) {
	rt, err := internalruntime.New(opts.config())
	if err != nil {
		return nil, err
	}
	return &Runtime{rt: rt}, nil
}

// NewWithListener is New with a listener the caller bound (OSS-SEAM-2): Start
// serves ln instead of binding Options.Addr, which may be empty or must name
// ln's address. Ownership: the Runtime owns ln only when NewWithListener
// returns no error, and then Shutdown closes it exactly once, whether or not
// Start succeeded. On an error the caller still owns ln, open.
func NewWithListener(opts Options, ln net.Listener) (*Runtime, error) {
	rt, err := internalruntime.NewWithListener(opts.config(), ln)
	if err != nil {
		return nil, err
	}
	return &Runtime{rt: rt}, nil
}

// HealthSnapshot is a read-only view of the runtime's health: whether it
// serves normal traffic, and the faults recorded since Start. A fatal fault
// means NOT-SERVING: normal routes answer 503 while /health keeps answering.
type HealthSnapshot struct {
	Serving bool
	Faults  []Fault
}

// Fault is one recorded fault. Reason never carries a URL or a credential:
// anything URL-shaped or a secret-named value is replaced before it leaves.
type Fault struct {
	Component string
	Fatal     bool
	Reason    string
}

var (
	urlShaped     = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S+`)
	secretValued  = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|key|dsn)=\S+`)
	redactedValue = "[redacted]"
)

// Health returns the current snapshot; before Start it is not serving and has
// no faults. The snapshot is a copy: changing it changes nothing.
func (r *Runtime) Health() HealthSnapshot {
	rep := r.rt.Report()
	if rep == nil {
		return HealthSnapshot{}
	}
	snap := HealthSnapshot{Serving: rep.Serving()}
	for _, f := range rep.Faults() {
		snap.Faults = append(snap.Faults, Fault{Component: f.Component, Fatal: f.Severity == lifecycle.SeverityFatal, Reason: scrubReason(f.Reason)})
	}
	return snap
}

// scrubReason removes anything URL-shaped and the value of a secret-named
// key=value pair from a fault reason.
func scrubReason(reason string) string {
	reason = urlShaped.ReplaceAllString(reason, redactedValue)
	return secretValued.ReplaceAllString(reason, "$1="+redactedValue)
}

// config maps every Options field to its private counterpart, copying the
// slices so a caller's later change cannot reach a running runtime.
func (o Options) config() internalruntime.Config {
	return internalruntime.Config{
		Addr:                      o.Addr,
		Issuer:                    o.Issuer,
		JWKSDBURL:                 o.DatabaseURL,
		RevocationCleanupInterval: o.RevocationCleanupInterval,
		Version:                   o.Version,
		Stdout:                    o.Stdout,
		Stderr:                    o.Stderr,
		Getenv:                    o.Getenv,
		DataDir:                   o.DataDir,
		UIPublicBaseURL:           o.UIPublicBaseURL,
		UIStaticDir:               o.UIStaticDir,
		MetricsAddr:               o.MetricsAddr,
		CORSAllowedOrigins:        slices.Clone(o.CORSAllowedOrigins),
		TrustedProxies:            slices.Clone(o.TrustedProxies),
		Restrictions:              slices.Clone(o.Restrictions),
	}
}

// errNotConstructed is returned by a Runtime that New did not build.
var errNotConstructed = errors.New("runtime: use runtime.New")

// Start opens the database, wires the services and serves on Options.Addr,
// exactly as the identuum-idp binary's serve path does.
func (r *Runtime) Start(ctx context.Context) error {
	if r == nil || r.rt == nil {
		return errNotConstructed
	}
	return r.rt.Start(ctx)
}

// Shutdown stops the runtime within ctx. It is safe before Start and when
// called twice.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil || r.rt == nil {
		return errNotConstructed
	}
	return r.rt.Shutdown(ctx)
}

// Done is closed when the runtime stops serving.
func (r *Runtime) Done() <-chan struct{} { return r.rt.Done() }

// ServeErr is the error that stopped serving, or nil.
func (r *Runtime) ServeErr() error { return r.rt.ServeErr() }

// Serving reports whether the runtime is serving normal traffic.
func (r *Runtime) Serving() bool { return r.rt.Serving() }

// Addr is the bound listen address after Start ("" before).
func (r *Runtime) Addr() string { return r.rt.Addr() }

// MetricsAddr is the bound metrics address after Start ("" when none).
func (r *Runtime) MetricsAddr() string { return r.rt.MetricsAddr() }
