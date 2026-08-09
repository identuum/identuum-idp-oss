package runtime

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// defaultSMTPTimeout bounds every post-dial SMTP op when
// IDENTUUM_IDP_SMTP_TIMEOUT is unset/malformed.
const defaultSMTPTimeout = 10 * time.Second

// resolveEmailNotifier builds the outbound-email notifier from the
// runtime's REAL config path — the Config.Getenv hook (os.Getenv in
// production) plus the secrets.EnvProvider for the SMTP password —
// exactly the mechanism the serving binary already uses for the MFA
// encryption key.
//
// Env convention (documented here + in the changelog):
//
//	IDENTUUM_IDP_SMTP_HOST      SMTP server host. REQUIRED to enable email.
//	IDENTUUM_IDP_SMTP_PORT      Port (default 587; 465 = implicit TLS).
//	IDENTUUM_IDP_SMTP_USERNAME  Optional; enables PlainAuth.
//	IDENTUUM_IDP_SMTP_PASSWORD  Optional; read via secrets.EnvProvider.
//	                            NEVER logged.
//	IDENTUUM_IDP_SMTP_FROM      Sender address. Falls back to _USERNAME.
//	IDENTUUM_IDP_SMTP_ALLOW_INSECURE  Opt-in to plaintext on the non-465
//	                            path when the server does not advertise
//	                            STARTTLS. Default false = fail closed.
//	                            AUTH over cleartext is refused regardless.
//	IDENTUUM_IDP_SMTP_TIMEOUT   Post-dial op deadline (Go duration, e.g.
//	                            "10s"). Default 10s. Bounds a stalled server.
//
// Returns (nil, reason) when email is NOT configured — the caller must
// then inject service.UnconfiguredEmailNotifier so every skipped send
// is explicit (honest degradation, F3/F4), never a silent no-op or a
// fake success. The returned mode string is safe to print: it never
// contains the password.
func resolveEmailNotifier(ctx context.Context, getenv func(string) string, linkBaseURL string) (*service.SMTPNotifier, string) {
	if getenv == nil {
		getenv = os.Getenv
	}

	host := strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_HOST"))
	if host == "" {
		return nil, "NOT CONFIGURED — password-reset / verification / activation emails will NOT be sent. Set IDENTUUM_IDP_SMTP_HOST (+ IDENTUUM_IDP_SMTP_FROM; optional _PORT/_USERNAME/_PASSWORD) to enable delivery"
	}

	username := strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_USERNAME"))
	from := strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_FROM"))
	if from == "" {
		from = username
	}
	if from == "" {
		// Host set but no usable sender — misconfigured. Stay honest:
		// no notifier, explicit reason.
		return nil, "MISCONFIGURED — IDENTUUM_IDP_SMTP_HOST is set but IDENTUUM_IDP_SMTP_FROM (and _USERNAME) are empty; emails will NOT be sent until a sender address is configured"
	}

	port := 587
	if raw := strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_PORT")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}

	// SMTP password via the in-OSS env secret provider (same pattern as
	// the MFA encryption key). Unset is fine — unauthenticated relay.
	// The value is handed to the notifier and NEVER logged.
	password := ""
	if pw, err := secrets.NewEnvProvider().GetSecret(ctx, "IDENTUUM_IDP_SMTP_PASSWORD"); err == nil {
		password = pw
	}

	// TLS opt-out (default false / fail-closed). strconv.ParseBool
	// accepts 1/t/T/TRUE/true/... and 0/f/F/FALSE/false/...; unset,
	// empty, or malformed ⇒ false so a typo never disables TLS.
	allowInsecure := false
	if v, err := strconv.ParseBool(strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_ALLOW_INSECURE"))); err == nil {
		allowInsecure = v
	}

	// Post-dial op timeout. time.ParseDuration ("10s", "30s"); unset or
	// malformed ⇒ defaultSMTPTimeout.
	timeout := defaultSMTPTimeout
	if raw := strings.TrimSpace(getenv("IDENTUUM_IDP_SMTP_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			timeout = d
		}
	}

	notifier := service.NewSMTPNotifier(service.SMTPNotifierConfig{
		Host:          host,
		Port:          port,
		Username:      username,
		Password:      password,
		From:          from,
		LinkBaseURL:   linkBaseURL,
		AllowInsecure: allowInsecure,
		Timeout:       timeout,
		Logger:        serviceLogger(), // P3-12
	})
	auth := "no-auth"
	if username != "" {
		auth = "plain-auth"
	}
	mode := fmt.Sprintf("smtp %s:%d (%s, from=%s, timeout=%s)", host, port, auth, from, timeout)
	if allowInsecure {
		// LOUD operator warning on the startup line: TLS is not required
		// on the non-465 path (a non-STARTTLS server may receive mail in
		// cleartext). AUTH over cleartext is still refused by the notifier.
		mode += " [INSECURE-PLAINTEXT-ALLOWED: IDENTUUM_IDP_SMTP_ALLOW_INSECURE is set — mail to a non-STARTTLS server is sent in CLEARTEXT]"
	}
	return notifier, mode
}
