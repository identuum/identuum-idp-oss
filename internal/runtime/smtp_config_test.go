package runtime

import (
	"context"
	"strings"
	"testing"
)

// (d) Unconfigured: no IDENTUUM_IDP_SMTP_HOST → no notifier + an
// explicit, truthful reason (used verbatim in the boot log).
func TestResolveEmailNotifier_Unconfigured(t *testing.T) {
	n, mode := resolveEmailNotifier(context.Background(), func(string) string { return "" }, "https://ui.example.com")
	if n != nil {
		t.Fatalf("expected nil notifier with no SMTP host, got %T", n)
	}
	if !strings.Contains(mode, "NOT CONFIGURED") || !strings.Contains(mode, "IDENTUUM_IDP_SMTP_HOST") {
		t.Errorf("unconfigured mode must state the truth + the fix; got %q", mode)
	}
}

// (d) Misconfigured: host set but no sender → still no notifier, with a
// reason naming the missing var (honest, actionable).
func TestResolveEmailNotifier_MisconfiguredNoFrom(t *testing.T) {
	env := map[string]string{"IDENTUUM_IDP_SMTP_HOST": "smtp.example.com"}
	n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
	if n != nil {
		t.Fatalf("expected nil notifier without a sender, got %T", n)
	}
	if !strings.Contains(mode, "MISCONFIGURED") || !strings.Contains(mode, "IDENTUUM_IDP_SMTP_FROM") {
		t.Errorf("misconfigured mode must name the missing var; got %q", mode)
	}
}

// (b)+(f) Configured: host+from → a real *service.SMTPNotifier; the
// mode string names host/port/from but NEVER the password.
func TestResolveEmailNotifier_Configured_ModeExcludesPassword(t *testing.T) {
	const secret = "TOP-SECRET-PW"
	t.Setenv("IDENTUUM_IDP_SMTP_PASSWORD", secret) // read via secrets.EnvProvider
	env := map[string]string{
		"IDENTUUM_IDP_SMTP_HOST":     "smtp.example.com",
		"IDENTUUM_IDP_SMTP_PORT":     "2525",
		"IDENTUUM_IDP_SMTP_USERNAME": "mailer",
		"IDENTUUM_IDP_SMTP_FROM":     "no-reply@example.com",
	}
	n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "https://ui.example.com")
	if n == nil {
		t.Fatal("expected a configured SMTP notifier")
	}
	if !strings.Contains(mode, "smtp.example.com:2525") || !strings.Contains(mode, "no-reply@example.com") {
		t.Errorf("mode should identify host:port + from; got %q", mode)
	}
	if strings.Contains(mode, secret) {
		t.Fatalf("mode string leaked the SMTP password: %q", mode)
	}
	if !strings.Contains(mode, "plain-auth") {
		t.Errorf("mode should note auth is enabled; got %q", mode)
	}
}

// FROM falls back to USERNAME when unset (documented convention).
func TestResolveEmailNotifier_FromFallsBackToUsername(t *testing.T) {
	env := map[string]string{
		"IDENTUUM_IDP_SMTP_HOST":     "smtp.example.com",
		"IDENTUUM_IDP_SMTP_USERNAME": "mailer@example.com",
	}
	n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
	if n == nil {
		t.Fatalf("expected notifier with username-as-from; mode=%q", mode)
	}
	if !strings.Contains(mode, "from=mailer@example.com") {
		t.Errorf("mode should show the fallback sender; got %q", mode)
	}
}

// P2-6: the insecure opt-out must LOUDLY flag the startup mode line, and
// the timeout must be reflected. Default (unset) must NOT carry the flag.
func TestResolveEmailNotifier_InsecureOptOutFlagsModeLoudly(t *testing.T) {
	base := map[string]string{
		"IDENTUUM_IDP_SMTP_HOST": "smtp.example.com",
		"IDENTUUM_IDP_SMTP_FROM": "no-reply@example.com",
	}
	// Default: no opt-out → mode must NOT flag insecure, and timeout=10s.
	_, mode := resolveEmailNotifier(context.Background(), func(k string) string { return base[k] }, "")
	if strings.Contains(mode, "INSECURE") {
		t.Errorf("default mode must not flag insecure; got %q", mode)
	}
	if !strings.Contains(mode, "timeout=10s") {
		t.Errorf("mode should show the default timeout; got %q", mode)
	}

	// Opt-out set → loud flag present.
	env := map[string]string{
		"IDENTUUM_IDP_SMTP_HOST":           "smtp.example.com",
		"IDENTUUM_IDP_SMTP_FROM":           "no-reply@example.com",
		"IDENTUUM_IDP_SMTP_ALLOW_INSECURE": "true",
		"IDENTUUM_IDP_SMTP_TIMEOUT":        "3s",
	}
	_, mode2 := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
	if !strings.Contains(mode2, "INSECURE-PLAINTEXT-ALLOWED") {
		t.Errorf("opt-out mode must loudly flag INSECURE-PLAINTEXT-ALLOWED; got %q", mode2)
	}
	if !strings.Contains(mode2, "CLEARTEXT") {
		t.Errorf("opt-out flag should warn about cleartext; got %q", mode2)
	}
	if !strings.Contains(mode2, "timeout=3s") {
		t.Errorf("mode should reflect the configured timeout; got %q", mode2)
	}
}
