package service

// smtp_notifier.go — real SMTP delivery for the three OSS notifier
// seams (PasswordResetNotifier, EmailVerificationNotifier,
// OrganizationActivationNotifier), plus the HONEST unconfigured
// fallback. Restores the email capability flagged as F3/F4 in
// docs/audit/release-readiness/codebase-integrity-audit-part1.md.
//
// The SMTP transport (implicit-TLS on port 465, context-aware STARTTLS
// elsewhere, PlainAuth only when credentials are present) is recovered
// from the retired notification_service.go (git history) and adapted to
// injected configuration — this file does NOT read env vars itself. The
// runtime resolves
// IDENTUUM_IDP_SMTP_* env into SMTPNotifierConfig (see
// internal/runtime/smtp_config.go) and injects the notifier in
// buildDeps.
//
// Secrets safety: the SMTP password is used only to build smtp.PlainAuth.
// It is NEVER logged, never included in error strings built here, and
// never echoed in email bodies.
//
// P-018: no panic / log.Fatal / os.Exit. A delivery failure returns an
// error; the consuming services treat sends as best-effort (log + keep
// the uniform wire response).

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
)

// emailKind* are the bounded Prometheus label values for
// metrics.EmailDelivery / EmailDeliveryDuration.
const (
	emailKindVerification  = "verification"
	emailKindActivation    = "activation"
	emailKindPasswordReset = "password_reset"
)

// ErrEmailDeliveryNotConfigured is returned by UnconfiguredEmailNotifier
// for every send attempt. It makes the "no SMTP configured" state
// explicit at each attempted delivery: the consuming services log it at
// Warn, so an operator sees exactly which emails were NOT sent and why —
// instead of a silent no-op.
var ErrEmailDeliveryNotConfigured = errors.New(
	"email delivery not configured: set IDENTUUM_IDP_SMTP_HOST (and IDENTUUM_IDP_SMTP_FROM) to enable outbound email")

// UnconfiguredEmailNotifier is the honest fallback injected by the
// runtime when SMTP is not configured. Every send returns
// ErrEmailDeliveryNotConfigured — never a fake success. The wire
// responses of the consuming services are unchanged (anti-enumeration
// messages stay uniform); honesty is delivered at the operator level
// (startup notice + per-attempt Warn logs).
type UnconfiguredEmailNotifier struct{}

func (UnconfiguredEmailNotifier) SendPasswordResetEmail(context.Context, *domain.User, string) error {
	return ErrEmailDeliveryNotConfigured
}

func (UnconfiguredEmailNotifier) SendVerificationEmail(context.Context, *domain.User, string) error {
	return ErrEmailDeliveryNotConfigured
}

func (UnconfiguredEmailNotifier) SendActivationEmail(context.Context, *domain.User, string, time.Time) error {
	return ErrEmailDeliveryNotConfigured
}

// SMTPNotifierConfig carries the resolved SMTP settings. All values are
// injected by the caller (the runtime's env resolver) — nothing here
// reads the environment.
type SMTPNotifierConfig struct {
	// Host is the SMTP server hostname. Required (the runtime only
	// constructs an SMTPNotifier when it is set).
	Host string
	// Port is the SMTP port. 465 uses implicit TLS (SMTPS); every other
	// port dials plain TCP and negotiates STARTTLS when the server
	// offers it. Non-positive defaults to 587.
	Port int
	// Username/Password enable smtp.PlainAuth when Username is
	// non-empty. Password is never logged.
	Username string
	Password string
	// From is the envelope/header sender. Required by the runtime
	// resolver (falls back to Username there).
	From string
	// LinkBaseURL is the browser-facing origin (no trailing slash)
	// used to build the verify-email / activation links. The
	// password-reset link is built by PasswordResetService and arrives
	// pre-composed.
	LinkBaseURL string
	// AllowInsecure, when true, permits delivery over a plaintext
	// (non-STARTTLS) connection on the non-465 path. Default false =
	// fail closed: a server that does not advertise STARTTLS is
	// refused rather than transacting AUTH + link in cleartext. Even
	// when true, a configured AUTH (Username non-empty) over a
	// non-TLS link is STILL refused — the SMTP password is never
	// transmitted in cleartext. Resolved from
	// IDENTUUM_IDP_SMTP_ALLOW_INSECURE.
	AllowInsecure bool
	// Timeout bounds every post-dial SMTP operation (AUTH, MAIL, RCPT,
	// DATA, Write, STARTTLS, QUIT) via a net.Conn deadline. net/smtp is
	// context-unaware, so without this a server that accepts then
	// stalls hangs the send forever. Non-positive defaults to 10s.
	// Resolved from IDENTUUM_IDP_SMTP_TIMEOUT.
	Timeout time.Duration
	// TLSConfig overrides the STARTTLS tls.Config. nil (the production
	// default) uses &tls.Config{ServerName: Host} — full verification.
	// Not env-resolved; exists so tests can inject a trust anchor and
	// operators with a private-CA internal relay can supply one.
	TLSConfig *tls.Config
	// Logger is optional; nil becomes zap.NewNop().
	Logger *zap.Logger
}

// SMTPNotifier delivers password-reset, email-verification, and
// organization-activation emails over SMTP. It satisfies
// PasswordResetNotifier, EmailVerificationNotifier, and
// OrganizationActivationNotifier.
type SMTPNotifier struct {
	host          string
	port          int
	username      string
	password      string
	from          string
	linkBaseURL   string
	allowInsecure bool
	timeout       time.Duration
	tlsConfig     *tls.Config
	logger        *zap.Logger
}

// defaultSMTPTimeout bounds every post-dial SMTP operation when the
// caller does not configure one.
const defaultSMTPTimeout = 10 * time.Second

// TLS-enforcement sentinels. Both wrap up through the "email delivery
// failed" error returned by sendEmail; callers/tests may errors.Is
// against them. Neither carries any secret.
var (
	// errSMTPTLSRequired: the non-465 server did not advertise STARTTLS
	// and the operator has not opted into insecure plaintext.
	errSMTPTLSRequired = errors.New("smtp: TLS required (server does not advertise STARTTLS)")
	// errSMTPAuthOverCleartext: AUTH is configured but TLS was not
	// established — refusing to transmit the SMTP password in cleartext,
	// even under the insecure opt-out.
	errSMTPAuthOverCleartext = errors.New("smtp: refusing to send AUTH credentials over a cleartext connection")
)

// NewSMTPNotifier builds the notifier. It performs no I/O and cannot
// fail; connectivity problems surface per-send as errors.
func NewSMTPNotifier(cfg SMTPNotifierConfig) *SMTPNotifier {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	port := cfg.Port
	if port <= 0 {
		port = 587
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultSMTPTimeout
	}
	return &SMTPNotifier{
		host:          cfg.Host,
		port:          port,
		username:      cfg.Username,
		password:      cfg.Password,
		from:          cfg.From,
		linkBaseURL:   strings.TrimRight(cfg.LinkBaseURL, "/"),
		allowInsecure: cfg.AllowInsecure,
		timeout:       timeout,
		tlsConfig:     cfg.TLSConfig,
		logger:        logger,
	}
}

// SendPasswordResetEmail delivers the pre-composed reset link.
func (s *SMTPNotifier) SendPasswordResetEmail(ctx context.Context, user *domain.User, resetLink string) error {
	subject := "Reset your password"
	body := fmt.Sprintf("You requested a password reset. Click the link below to set a new password:\n\n%s\n\nThis link expires in 1 hour. If you did not request a reset, ignore this email.", resetLink)
	if user.Name != nil {
		body = fmt.Sprintf("Hello %s,\n\n%s", *user.Name, body)
	}
	return s.sendEmail(ctx, emailKindPasswordReset, user.Email, subject, body)
}

// SendVerificationEmail builds the verify-email link from LinkBaseURL
// and delivers it.
func (s *SMTPNotifier) SendVerificationEmail(ctx context.Context, user *domain.User, rawToken string) error {
	params := url.Values{}
	params.Set("token", rawToken)
	verifyURL := s.linkBaseURL + "/verify-email?" + params.Encode()

	subject := "Verify your email address"
	body := fmt.Sprintf("Please verify your email address by clicking the link below:\n\n%s\n\nExpiration: 24 hours.", verifyURL)
	if user.Name != nil {
		body = fmt.Sprintf("Hello %s,\n\n%s", *user.Name, body)
	}
	return s.sendEmail(ctx, emailKindVerification, user.Email, subject, body)
}

// SendActivationEmail builds the organization-activation link from
// LinkBaseURL and delivers it.
func (s *SMTPNotifier) SendActivationEmail(ctx context.Context, user *domain.User, rawToken string, expiresAt time.Time) error {
	params := url.Values{}
	params.Set("token", rawToken)
	activationURL := s.linkBaseURL + "/activate?" + params.Encode()

	subject := "Activate your Organization"
	if user.OrganizationName != nil {
		subject = fmt.Sprintf("Activate your Organization: %s", *user.OrganizationName)
	}
	body := fmt.Sprintf("You have been designated as the administrator for a new organization.\n\n"+
		"Please activate your account and set up your credentials by clicking the link below:\n\n"+
		"%s\n\n"+
		"This link expires at %s.", activationURL, expiresAt.Format(time.RFC1123))
	if user.Name != nil {
		body = fmt.Sprintf("Hello %s,\n\n%s", *user.Name, body)
	}
	return s.sendEmail(ctx, emailKindActivation, user.Email, subject, body)
}

// sendEmail is the unified SMTP delivery helper (transport recovered
// from the retired notification_service.go).
//
//   - Port 465 uses implicit TLS (SMTPS) via tls.Dialer + smtp.NewClient.
//   - All other ports dial plain TCP with the caller's context and
//     negotiate STARTTLS when the server advertises it.
//   - smtp.PlainAuth is used only when a username is configured.
//
// The recipient is masked in logs; the password is NEVER logged.
func (s *SMTPNotifier) sendEmail(ctx context.Context, kind, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		s.from, to, subject, body))

	start := time.Now()
	var deliveryErr error
	if s.port == 465 {
		deliveryErr = s.sendViaImplicitTLS(ctx, addr, to, auth, msg)
	} else {
		deliveryErr = s.sendViaSTARTTLS(ctx, addr, to, auth, msg)
	}
	metrics.EmailDeliveryDuration.WithLabelValues(kind).Observe(time.Since(start).Seconds())

	if deliveryErr != nil {
		metrics.EmailDelivery.WithLabelValues(kind, "relay_error").Inc()
		s.logger.Error("smtp: email delivery failed",
			zap.String("kind", kind),
			zap.String("to", maskEmail(to)),
			zap.Error(deliveryErr),
		)
		return fmt.Errorf("email delivery failed: %w", deliveryErr)
	}

	metrics.EmailDelivery.WithLabelValues(kind, "sent").Inc()
	s.logger.Info("smtp: email sent",
		zap.String("kind", kind),
		zap.String("to", maskEmail(to)),
	)
	return nil
}

// postDialDeadline is the absolute deadline applied to the net.Conn
// after a successful dial so every context-unaware net/smtp op (AUTH,
// MAIL, RCPT, DATA, Write, STARTTLS, QUIT) is bounded. It is
// now+timeout, or the caller's ctx deadline when that is sooner — a
// stalled server fails within ~timeout instead of hanging forever.
func (s *SMTPNotifier) postDialDeadline(ctx context.Context) time.Time {
	dl := time.Now().Add(s.timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	return dl
}

// sendViaImplicitTLS connects using implicit TLS (port 465 / SMTPS).
// smtp.SendMail only supports STARTTLS; this helper handles SMTPS.
func (s *SMTPNotifier) sendViaImplicitTLS(ctx context.Context, addr, to string, auth smtp.Auth, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: s.host}
	conn, err := (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	// Bound every post-dial op (net/smtp is context-unaware).
	_ = conn.SetDeadline(s.postDialDeadline(ctx))
	// conn is passed to smtp.NewClient; on success the client owns the
	// connection. On failure we close it here explicitly.
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	return smtpTransact(client, s.from, to, auth, msg)
}

// sendViaSTARTTLS connects with a context-aware plain TCP dial, then
// REQUIRES STARTTLS: TLS must be established before any AUTH or message
// bytes leave the process. Fail-closed by default — a server that does
// not advertise STARTTLS (or a MITM that strips it from EHLO) is refused
// rather than transacting in cleartext.
func (s *SMTPNotifier) sendViaSTARTTLS(ctx context.Context, addr, to string, auth smtp.Auth, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %w", err)
	}
	// Bound every post-dial op (net/smtp is context-unaware).
	_ = conn.SetDeadline(s.postDialDeadline(ctx))
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := s.tlsConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{ServerName: s.host}
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			// StartTLS failed AFTER it was advertised — fail closed, never
			// fall through to a cleartext transaction.
			return fmt.Errorf("STARTTLS negotiation failed: %w", err)
		}
	} else {
		// The server did NOT advertise STARTTLS. Refuse to send in
		// cleartext unless the operator explicitly opted in.
		if !s.allowInsecure {
			return errSMTPTLSRequired
		}
		// Insecure opt-out is active: plaintext delivery is permitted —
		// EXCEPT we NEVER transmit AUTH credentials over an unencrypted
		// link, even under the opt-out.
		if auth != nil {
			return errSMTPAuthOverCleartext
		}
	}

	return smtpTransact(client, s.from, to, auth, msg)
}

// smtpTransact runs AUTH (when configured) + MAIL/RCPT/DATA/QUIT on an
// established client. Shared by both transport paths.
func smtpTransact(client *smtp.Client, from, to string, auth smtp.Auth, msg []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP message write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP message close failed: %w", err)
	}
	return client.Quit()
}

// maskEmail partially redacts an email address for safe log output.
// e.g. "john.doe@example.com" → "j*******@example.com"
func maskEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	local := email[:at]
	if len(local) <= 1 {
		return "*" + email[at:]
	}
	return string(local[0]) + strings.Repeat("*", len(local)-1) + email[at:]
}
