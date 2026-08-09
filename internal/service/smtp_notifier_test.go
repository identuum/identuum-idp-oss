package service

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// fakeSMTPSession is what the in-test SMTP server captured from one
// full delivery conversation.
type fakeSMTPSession struct {
	mailFrom string
	rcptTo   string
	data     string
	err      error
}

// startFakeSMTPServer runs a minimal plaintext SMTP server (no
// STARTTLS advertised, no AUTH) on 127.0.0.1:0 that accepts exactly
// one delivery and reports it on the returned channel. This exercises
// the REAL net/smtp client path in SMTPNotifier end-to-end.
func startFakeSMTPServer(t *testing.T) (addr string, sessions <-chan fakeSMTPSession) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake smtp listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan fakeSMTPSession, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- fakeSMTPSession{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		var sess fakeSMTPSession
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		reply := func(s string) {
			_, _ = w.WriteString(s + "\r\n")
			_ = w.Flush()
		}

		reply("220 fakesmtp ready")
		inData := false
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				sess.err = fmt.Errorf("read: %w", err)
				ch <- sess
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					sess.data = data.String()
					reply("250 OK: queued")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				reply("250-fakesmtp")
				reply("250 8BITMIME") // deliberately NO STARTTLS extension
			case strings.HasPrefix(upper, "MAIL FROM:"):
				sess.mailFrom = line[len("MAIL FROM:"):]
				reply("250 OK")
			case strings.HasPrefix(upper, "RCPT TO:"):
				sess.rcptTo = line[len("RCPT TO:"):]
				reply("250 OK")
			case upper == "DATA":
				inData = true
				reply("354 End data with <CR><LF>.<CR><LF>")
			case upper == "QUIT":
				reply("221 Bye")
				ch <- sess
				return
			default:
				reply("250 OK")
			}
		}
	}()
	return ln.Addr().String(), ch
}

func smtpTestUser(email string) *domain.User {
	return &domain.User{ID: uuid.New(), Email: email}
}

// (c) CONFIGURED: the real SMTPNotifier delivers a verification email
// over an actual SMTP conversation — right recipient, and the body
// carries the verify link built from LinkBaseURL + the raw token.
func TestSMTPNotifier_SendVerificationEmail_RealSMTP(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host:        host,
		Port:        port,
		From:        "no-reply@idp.test",
		LinkBaseURL: "https://ui.example.com/",
		// The fake server advertises no STARTTLS and no AUTH; this test
		// exercises message composition over the plaintext transaction
		// path, which is fail-closed by default now — opt in explicitly.
		AllowInsecure: true,
	})
	err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "RAWTOKEN123")
	if err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	sess := <-sessions
	if sess.err != nil {
		t.Fatalf("fake smtp session: %v", sess.err)
	}
	if !strings.Contains(sess.rcptTo, "alice@example.com") {
		t.Errorf("RCPT TO = %q, want the user's email", sess.rcptTo)
	}
	if !strings.Contains(sess.data, "https://ui.example.com/verify-email?token=RAWTOKEN123") {
		t.Errorf("message body missing the verify link; data=\n%s", sess.data)
	}
	if !strings.Contains(sess.mailFrom, "no-reply@idp.test") {
		t.Errorf("MAIL FROM = %q, want the configured sender", sess.mailFrom)
	}
}

// (c) CONFIGURED: the reset email carries the pre-composed reset link
// to the right recipient.
func TestSMTPNotifier_SendPasswordResetEmail_RealSMTP(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	n := NewSMTPNotifier(SMTPNotifierConfig{Host: host, Port: port, From: "no-reply@idp.test", AllowInsecure: true})
	resetLink := "https://ui.example.com/reset-password?token=RESET456"
	if err := n.SendPasswordResetEmail(context.Background(), smtpTestUser("bob@example.com"), resetLink); err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}
	sess := <-sessions
	if !strings.Contains(sess.rcptTo, "bob@example.com") {
		t.Errorf("RCPT TO = %q, want bob@example.com", sess.rcptTo)
	}
	if !strings.Contains(sess.data, resetLink) {
		t.Errorf("message body missing the reset link; data=\n%s", sess.data)
	}
}

// (d) UNCONFIGURED: every send returns the explicit sentinel — never a
// fake success, never a silent no-op.
func TestUnconfiguredEmailNotifier_ReturnsExplicitError(t *testing.T) {
	n := UnconfiguredEmailNotifier{}
	u := smtpTestUser("x@example.com")
	if err := n.SendPasswordResetEmail(context.Background(), u, "link"); !errors.Is(err, ErrEmailDeliveryNotConfigured) {
		t.Errorf("reset: err = %v, want ErrEmailDeliveryNotConfigured", err)
	}
	if err := n.SendVerificationEmail(context.Background(), u, "tok"); !errors.Is(err, ErrEmailDeliveryNotConfigured) {
		t.Errorf("verify: err = %v, want ErrEmailDeliveryNotConfigured", err)
	}
	if err := n.SendActivationEmail(context.Background(), u, "tok", time.Now()); !errors.Is(err, ErrEmailDeliveryNotConfigured) {
		t.Errorf("activation: err = %v, want ErrEmailDeliveryNotConfigured", err)
	}
}

// (d) UNCONFIGURED, end-to-end through the reset service: the wire
// contract is unchanged (uniform nil → 200 anti-enumeration response),
// but the skipped send is HONESTLY surfaced as a Warn log carrying
// ErrEmailDeliveryNotConfigured — not silently dropped.
func TestRequestPasswordReset_UnconfiguredNotifierLogsHonestFailure(t *testing.T) {
	user := &domain.User{ID: uuid.New(), Email: "carol@example.com"}
	core, logs := observer.New(zap.WarnLevel)
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:              newFakeUserRepo(user),
		Resets:             newFakePasswordResetRepo(),
		Audit:              audit.NoopService{},
		Notifier:           UnconfiguredEmailNotifier{},
		HumanFacingBaseURL: "https://ui.example.com",
		Logger:             zap.New(core),
	})

	// Wire contract unchanged: uniform success (anti-enumeration).
	if err := svc.RequestPasswordReset(context.Background(), "carol@example.com", "1.2.3.4", "ua"); err != nil {
		t.Fatalf("RequestPasswordReset: %v (uniform nil expected)", err)
	}

	// Honest operator-visible failure.
	found := false
	for _, e := range logs.All() {
		if e.Message == "password_reset: send email failed" {
			found = true
			for _, f := range e.Context {
				if f.Key == "error" && strings.Contains(fmt.Sprint(f.Interface), "email delivery not configured") {
					return // sentinel surfaced — fully honest
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected a 'password_reset: send email failed' Warn log for the unconfigured notifier; got %d logs", logs.Len())
	}
	t.Fatalf("Warn log found but without the explicit not-configured error")
}

// (d)/(e) UNCONFIGURED, end-to-end through the verification service
// (the T2 companion): the uniform anti-enumeration behavior is
// unchanged, but the skipped verification send surfaces as an honest
// Warn log with the explicit not-configured error.
func TestResendVerification_UnconfiguredNotifierIsHonest(t *testing.T) {
	user := &domain.User{ID: uuid.New(), Email: "erin@example.com", EmailVerified: false}
	core, logs := observer.New(zap.WarnLevel)
	svc := NewEmailVerificationService(
		newFakeUserRepo(user),
		newFakeEmailVerificationRepo(),
		UnconfiguredEmailNotifier{},
		audit.NoopService{},
		EmailVerificationServiceOptions{Logger: zap.New(core)},
	)

	if err := svc.ResendVerification(context.Background(), "erin@example.com"); err != nil {
		t.Fatalf("ResendVerification: %v (uniform nil expected)", err)
	}
	for _, e := range logs.All() {
		if e.Message == "email_verification: send email failed" {
			for _, f := range e.Context {
				if f.Key == "error" && strings.Contains(fmt.Sprint(f.Interface), "email delivery not configured") {
					return // honest failure surfaced
				}
			}
		}
	}
	t.Fatalf("expected an honest 'send email failed' Warn with the not-configured error; got %d warn logs", logs.Len())
}

// (f) The SMTP password is NEVER logged — even on the error path. The
// notifier is pointed at a dead endpoint so delivery fails and the
// error path logs; no log entry may contain the secret.
func TestSMTPNotifier_PasswordNeverLogged(t *testing.T) {
	const secret = "SUPER-SECRET-SMTP-PASSWORD"
	core, logs := observer.New(zap.DebugLevel)

	// 127.0.0.1:1 — reliably refused; forces the error/logging path.
	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host:     "127.0.0.1",
		Port:     1,
		Username: "mailer",
		Password: secret,
		From:     "no-reply@idp.test",
		Logger:   zap.New(core),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := n.SendPasswordResetEmail(ctx, smtpTestUser("dave@example.com"), "https://ui/reset?token=x")
	if err == nil {
		t.Fatal("expected delivery error against a dead endpoint")
	}
	// PREMISE: the failure must have LOGGED something. A notifier that logs
	// nothing has nothing to leak, and the sweep below would pass vacuously
	// while the very behaviour under test — error logging — is absent (V4).
	if logs.Len() == 0 {
		t.Fatal("delivery failed but nothing was logged — an empty log cannot leak, so the sweep below would prove nothing")
	}
	for _, e := range logs.All() {
		line := e.Message
		for _, f := range e.Context {
			line += " " + f.Key + "=" + fmt.Sprint(f.Interface) + fmt.Sprint(f.String)
		}
		if strings.Contains(line, secret) {
			t.Fatalf("SMTP password leaked into logs: %q", line)
		}
	}
	// The error string itself carries no secret either. This assertion was a
	// dangling COMMENT with no code for its whole life — the promise existed,
	// the check did not.
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("SMTP password leaked into the returned error: %v", err)
	}
}

// ---------- P2-6: TLS enforcement + post-connect deadline ----------

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

func recvSession(t *testing.T, ch <-chan fakeSMTPSession, d time.Duration) fakeSMTPSession {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(d):
		t.Fatalf("no fake-smtp session within %s", d)
		return fakeSMTPSession{}
	}
}

// selfSignedTLSConfig returns a SERVER tls.Config bearing a fresh
// self-signed cert for 127.0.0.1. Clients trust it via
// InsecureSkipVerify (the test injects that through
// SMTPNotifierConfig.TLSConfig).
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// startFakeSTARTTLSServer advertises STARTTLS, upgrades the connection on
// the STARTTLS verb, and runs the rest of the conversation over TLS.
func startFakeSTARTTLSServer(t *testing.T, serverTLS *tls.Config) (addr string, sessions <-chan fakeSMTPSession) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starttls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan fakeSMTPSession, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- fakeSMTPSession{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		var sess fakeSMTPSession
		var nc net.Conn = conn
		r := bufio.NewReader(nc)
		w := bufio.NewWriter(nc)
		reply := func(s string) {
			_, _ = w.WriteString(s + "\r\n")
			_ = w.Flush()
		}
		reply("220 fakestarttls ready")
		inData := false
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				sess.err = fmt.Errorf("read: %w", err)
				ch <- sess
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					sess.data = data.String()
					reply("250 OK: queued")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				reply("250-fakestarttls")
				reply("250 STARTTLS")
			case upper == "STARTTLS":
				reply("220 Ready to start TLS")
				tconn := tls.Server(nc, serverTLS)
				if err := tconn.Handshake(); err != nil {
					sess.err = fmt.Errorf("server tls handshake: %w", err)
					ch <- sess
					return
				}
				nc = tconn
				r = bufio.NewReader(nc)
				w = bufio.NewWriter(nc)
			case strings.HasPrefix(upper, "MAIL FROM:"):
				sess.mailFrom = line[len("MAIL FROM:"):]
				reply("250 OK")
			case strings.HasPrefix(upper, "RCPT TO:"):
				sess.rcptTo = line[len("RCPT TO:"):]
				reply("250 OK")
			case upper == "DATA":
				inData = true
				reply("354 End data with <CR><LF>.<CR><LF>")
			case upper == "QUIT":
				reply("221 Bye")
				ch <- sess
				return
			default:
				reply("250 OK")
			}
		}
	}()
	return ln.Addr().String(), ch
}

// startStallSMTPServer accepts, sends the 220 greeting, then goes silent
// forever — it never answers EHLO. Used to prove the post-dial deadline
// bounds a stalled server.
func startStallSMTPServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stall listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("220 stall ready\r\n"))
		// Read and discard forever; never reply again.
		buf := make([]byte, 256)
		for {
			if _, err := conn.Read(buf); err != nil {
				_ = conn.Close()
				return
			}
		}
	}()
	return ln.Addr().String()
}

// TEST 1: no-STARTTLS server + default config → send FAILS; no message
// bytes leave in cleartext. TEETH: revert sendViaSTARTTLS to "if
// advertised" (fall through when not) and this fails (send succeeds).
func TestSMTPNotifier_NoSTARTTLS_DefaultFailsClosed(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t) // advertises NO STARTTLS
	host, port := hostPort(t, addr)

	n := NewSMTPNotifier(SMTPNotifierConfig{Host: host, Port: port, From: "no-reply@idp.test"})
	err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "RAWTOKEN")
	if err == nil {
		t.Fatal("send SUCCEEDED over a non-STARTTLS server with default config — cleartext leak")
	}
	if !errors.Is(err, errSMTPTLSRequired) {
		t.Fatalf("err = %v, want errSMTPTLSRequired", err)
	}
	// No message/AUTH bytes were transmitted (only the EHLO handshake).
	sess := recvSession(t, sessions, 3*time.Second)
	if sess.mailFrom != "" || sess.rcptTo != "" || sess.data != "" {
		t.Fatalf("cleartext bytes leaked: mailFrom=%q rcptTo=%q data=%q", sess.mailFrom, sess.rcptTo, sess.data)
	}
}

// TEST 2: opt-out + NO auth + no-STARTTLS → send SUCCEEDS in plaintext.
func TestSMTPNotifier_NoSTARTTLS_OptOutNoAuthSucceeds(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, port := hostPort(t, addr)

	n := NewSMTPNotifier(SMTPNotifierConfig{Host: host, Port: port, From: "no-reply@idp.test", AllowInsecure: true})
	if err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "TOK"); err != nil {
		t.Fatalf("opt-out plaintext send should succeed: %v", err)
	}
	sess := recvSession(t, sessions, 3*time.Second)
	if !strings.Contains(sess.rcptTo, "alice@example.com") {
		t.Fatalf("RCPT TO = %q", sess.rcptTo)
	}
}

// TEST 3: opt-out + auth configured + no-STARTTLS → send FAILS; the
// password is NEVER transmitted in cleartext.
func TestSMTPNotifier_NoSTARTTLS_OptOutWithAuthStillFails(t *testing.T) {
	addr, sessions := startFakeSMTPServer(t)
	host, port := hostPort(t, addr)

	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host: host, Port: port, From: "no-reply@idp.test",
		Username: "mailer", Password: "SECRET-PW",
		AllowInsecure: true, // opt-out is on, but AUTH-over-cleartext must STILL fail
	})
	err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "TOK")
	if err == nil {
		t.Fatal("AUTH over cleartext SUCCEEDED — the SMTP password would have been sent in the clear")
	}
	if !errors.Is(err, errSMTPAuthOverCleartext) {
		t.Fatalf("err = %v, want errSMTPAuthOverCleartext", err)
	}
	// The server never received AUTH/MAIL/RCPT/DATA.
	sess := recvSession(t, sessions, 3*time.Second)
	if sess.mailFrom != "" || sess.rcptTo != "" || sess.data != "" {
		t.Fatalf("transacted after auth-over-cleartext guard should have fired: %+v", sess)
	}
}

// TEST 4: STARTTLS advertised → TLS negotiated → send succeeds.
func TestSMTPNotifier_STARTTLSNegotiated_Succeeds(t *testing.T) {
	addr, sessions := startFakeSTARTTLSServer(t, selfSignedTLSConfig(t))
	host, port := hostPort(t, addr)

	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host: host, Port: port, From: "no-reply@idp.test",
		LinkBaseURL: "https://ui.example.com",
		TLSConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test trusts the in-test self-signed cert
	})
	if err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "RAWTOKEN"); err != nil {
		t.Fatalf("STARTTLS send should succeed: %v", err)
	}
	sess := recvSession(t, sessions, 3*time.Second)
	if !strings.Contains(sess.rcptTo, "alice@example.com") {
		t.Fatalf("RCPT TO = %q (expected over TLS)", sess.rcptTo)
	}
	if !strings.Contains(sess.data, "https://ui.example.com/verify-email?token=RAWTOKEN") {
		t.Fatalf("verify link missing from TLS-delivered message; data=\n%s", sess.data)
	}
}

// TEST 5: a server that accepts then stalls → send returns within
// ~timeout, never hangs. TEETH: remove conn.SetDeadline and this exceeds
// its bound (hangs to the go-test timeout).
func TestSMTPNotifier_StalledServerFailsWithinTimeout(t *testing.T) {
	addr := startStallSMTPServer(t)
	host, port := hostPort(t, addr)

	n := NewSMTPNotifier(SMTPNotifierConfig{
		Host: host, Port: port, From: "no-reply@idp.test",
		AllowInsecure: true,                   // isolate the stall (not TLS-required)
		Timeout:       300 * time.Millisecond, // tight bound for the test
	})
	start := time.Now()
	err := n.SendVerificationEmail(context.Background(), smtpTestUser("alice@example.com"), "TOK")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("stalled server: expected a timeout error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("send hung %s — post-dial deadline not enforced", elapsed)
	}
}
