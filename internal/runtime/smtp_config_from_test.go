package runtime

import (
	"context"
	"strings"
	"testing"
)

// A sender that is not one email address is refused at startup in plain
// words: no notifier (the runtime injects the honest unconfigured notifier)
// and a MISCONFIGURED reason naming the variable. At 3e1fa09 any non-empty
// string is accepted and every later send fails at MAIL FROM.
//
// RULE: SMTP-FROM-ENVELOPE-1 — the startup half: a sender that is not one
// address is refused in plain words and no mail is attempted.
func TestResolveEmailNotifier_InvalidFromRefused(t *testing.T) {
	for _, from := range []string{"not an address", "a@b.test, c@d.test", "Name <>"} {
		env := map[string]string{"IDENTUUM_IDP_SMTP_HOST": "smtp.example.com", "IDENTUUM_IDP_SMTP_FROM": from}
		n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
		if n != nil {
			t.Errorf("SMTP_FROM %q: expected no notifier, got one (mode %q)", from, mode)
		}
		if !strings.Contains(mode, "MISCONFIGURED") || !strings.Contains(mode, "IDENTUUM_IDP_SMTP_FROM") {
			t.Errorf("SMTP_FROM %q: mode must say MISCONFIGURED and name IDENTUUM_IDP_SMTP_FROM; got %q", from, mode)
		}
	}
}

// The username fallback is held to the same rule: a USERNAME that is not an
// address (an API-key login name) is not a sender.
func TestResolveEmailNotifier_UsernameFallbackMustBeAnAddress(t *testing.T) {
	env := map[string]string{"IDENTUUM_IDP_SMTP_HOST": "smtp.example.com", "IDENTUUM_IDP_SMTP_USERNAME": "apikey"}
	n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
	if n != nil {
		t.Errorf("USERNAME fallback %q: expected no notifier, got one (mode %q)", "apikey", mode)
	}
	if !strings.Contains(mode, "MISCONFIGURED") || !strings.Contains(mode, "IDENTUUM_IDP_SMTP_FROM") {
		t.Errorf("mode must say MISCONFIGURED and name IDENTUUM_IDP_SMTP_FROM; got %q", mode)
	}
}

// Control: the display-name form is accepted and the mode line shows it.
func TestResolveEmailNotifier_DisplayNameFromAccepted(t *testing.T) {
	env := map[string]string{"IDENTUUM_IDP_SMTP_HOST": "smtp.example.com", "IDENTUUM_IDP_SMTP_FROM": "Identuum <no-reply@example.com>"}
	n, mode := resolveEmailNotifier(context.Background(), func(k string) string { return env[k] }, "")
	if n == nil {
		t.Fatalf("expected a notifier for a display-name sender; mode=%q", mode)
	}
	if !strings.Contains(mode, "no-reply@example.com") {
		t.Errorf("mode should name the sender address; got %q", mode)
	}
}
