// target: internal/service/smtp_notifier_display_name_test.go (OSS-0913-C item 1, red first)
package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// SMTP_FROM may carry a display name ("Name <addr>"). The SMTP envelope
// (MAIL FROM) takes the bare address only (RFC 5321 reverse-path); the
// From header keeps the display name. At 3e1fa09 the whole string goes into
// MAIL FROM:<...>, which a real relay refuses with 501, so no mail leaves.
func TestSMTPNotifier_DisplayNameFrom_EnvelopeIsBareAddress(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host:          host,
		Port:          port,
		From:          "Identuum acceptance <no-reply@idp.test>",
		LinkBaseURL:   "https://ui.example.com",
		AllowInsecure: true,
	})
	if err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "TOKEN"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	sess := <-sessions
	if sess.err != nil {
		t.Fatalf("fake smtp session: %v", sess.err)
	}
	if got, want := reversePath(sess.mailFrom), "<no-reply@idp.test>"; got != want {
		t.Errorf("MAIL FROM = %q, want %q (bare address; a relay answers 501 to anything else)", got, want)
	}
	header := ""
	for _, line := range strings.Split(sess.data, "\n") {
		if strings.HasPrefix(line, "From: ") {
			header = line
			break
		}
	}
	if !strings.Contains(header, "Identuum acceptance") || !strings.Contains(header, "<no-reply@idp.test>") {
		t.Errorf("From header = %q, want the display name and <no-reply@idp.test>", header)
	}
}

// reversePath is the MAIL FROM argument up to its first ">" (drops the
// BODY=8BITMIME parameter net/smtp adds when the server offers 8BITMIME).
func reversePath(mailFrom string) string {
	s := strings.TrimSpace(mailFrom)
	if i := strings.Index(s, ">"); i >= 0 {
		return s[:i+1]
	}
	return s
}

// Control: a bare SMTP_FROM keeps working exactly at the envelope.
func TestSMTPNotifier_BareFrom_EnvelopeUnchanged(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	n := NewSMTPNotifier(SMTPNotifierConfig{Host: host, Port: port, From: "no-reply@idp.test", AllowInsecure: true})
	if err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "TOKEN"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	sess := <-sessions
	if got, want := reversePath(sess.mailFrom), "<no-reply@idp.test>"; got != want {
		t.Errorf("MAIL FROM = %q, want %q", got, want)
	}
	if !strings.Contains(sess.data, "no-reply@idp.test") {
		t.Errorf("From header lost the address; data=\n%s", sess.data)
	}
}
