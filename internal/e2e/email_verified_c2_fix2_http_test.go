//go:build integration

// Package e2e — OSS-0912-C2-FIX-2 (review OSS-0912-C2-FIX-REVIEW F1, F2),
// through the whole OSS engine on the test database:
//
//   - An address change that commits while a verification link is being
//     opened never leaves the NEW address proven (F1; the review's
//     TestRV_RaceVerifyThenChange, kept, and its HTTP race in bounded rounds).
//   - The public resend never mails the site_admin's reserved address, and
//     its answer stays the same plain 200 (F2).
//
// Tokens, links and passwords are never printed.
package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// putEmail changes the user's address through the administrator's PUT.
func (w *inviteWorld) putEmail(id, address string) int {
	st, _, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, `{"email":"`+address+`"}`)
	return st
}

// proofRow reads the user's stored address and how its mailbox was proven.
func (w *inviteWorld) proofRow(id string) (email, via string) {
	w.t.Helper()
	var v *string
	if err := w.pool.QueryRow(w.ctx, `SELECT email, email_verified_via FROM users WHERE id = $1`, id).Scan(&email, &v); err != nil {
		w.t.Fatalf("read user row: %v", err)
	}
	if v != nil {
		via = *v
	}
	return email, via
}

// changeOnRead lets the administrator's address change commit right after
// VerifyEmail's read of the user, before anything is written.
type changeOnRead struct {
	repository.UserRepository
	w       *inviteWorld
	newAddr string
	once    sync.Once
	putCode int
}

func (r *changeOnRead) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := r.UserRepository.GetByID(ctx, id)
	if err == nil && u != nil {
		r.once.Do(func() { r.putCode = r.w.putEmail(id.String(), r.newAddr) })
	}
	return u, err
}

// F1, the review's red test with a fixed interleaving: verify reads the user
// (address A), the administrator's change to B commits, verify goes on.
func TestE2E_OSS_C2_ChangeDuringVerifyDoesNotProveNewAddress(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	a := "c2fix2-race-a-" + uuid.NewString()[:8] + "@example.invalid"
	b := "c2fix2-race-b-" + uuid.NewString()[:8] + "@example.invalid"
	id := w.adminSetUser(a)
	link := w.verificationLinkFor(id, a)
	users := &changeOnRead{UserRepository: w.repos.User, w: w, newAddr: b}
	svc := service.NewEmailVerificationService(users, w.repos.EmailVerification, nil, nil, service.EmailVerificationServiceOptions{})

	err := svc.VerifyEmail(w.ctx, link, "127.0.0.1", "c2fix2")
	if users.putCode != http.StatusOK {
		t.Fatalf("the concurrent change = %d; want 200 (the interleaving did not happen)", users.putCode)
	}
	email, via := w.proofRow(id)
	if email != b {
		t.Fatalf("the stored address is not B after the change")
	}
	if err == nil {
		t.Errorf("VerifyEmail = nil; want a refusal (the address changed while the link was opened)")
	}
	if via == domain.EmailVerifiedViaEmailLink {
		t.Errorf("the never-mailed address B is recorded proven (email_link)")
	}
	cb, _ := w.c2Bearers(uuid.MustParse(id))
	if ui := w.userinfoEmailVerified(cb); ui != false {
		t.Errorf("userinfo email_verified for B = %v; want false", ui)
	}
}

// F1 over HTTP: the link is opened and the address changed at the same
// time, in bounded rounds. No round may leave the new address proven.
func TestE2E_OSS_C2_ConcurrentVerifyAndChangeOverHTTP(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	const rounds = 30
	bad := 0
	outcomes := map[string]int{}
	for i := 0; i < rounds; i++ {
		a := "c2fix2-hr-a-" + uuid.NewString()[:8] + "@example.invalid"
		b := "c2fix2-hr-b-" + uuid.NewString()[:8] + "@example.invalid"
		id := w.adminSetUser(a)
		link := w.verificationLinkFor(id, a)
		var wg sync.WaitGroup
		var vst, pst int
		wg.Add(2)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, w.base+"/api/v1/auth/verify-email?token="+link, nil)
			if res, err := http.DefaultClient.Do(req); err == nil {
				vst = res.StatusCode
				_ = res.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPut, w.base+"/api/v1/users/"+id, strings.NewReader(`{"email":"`+b+`"}`))
			req.Header.Set("Authorization", "Bearer "+w.bearers["adminA"])
			req.Header.Set("Content-Type", "application/json")
			if res, err := http.DefaultClient.Do(req); err == nil {
				pst = res.StatusCode
				_ = res.Body.Close()
			}
		}()
		wg.Wait()
		if pst != http.StatusOK {
			t.Fatalf("round %d: the change = %d; want 200", i, pst)
		}
		email, via := w.proofRow(id)
		outcomes[http.StatusText(vst)+"/"+via]++
		if email == b && via == domain.EmailVerifiedViaEmailLink {
			bad++
		}
	}
	t.Logf("rounds=%d outcomes=%v new-address-proven=%d", rounds, outcomes, bad)
	if bad != 0 {
		t.Errorf("the never-mailed new address was recorded proven in %d of %d rounds", bad, rounds)
	}
}

// F1, defence in depth: the proof write names the address it checked, and
// matches no row once the address is another one.
func TestE2E_OSS_C2_ProofWriteRequiresTheCheckedAddress(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	a := "c2fix2-cw-a-" + uuid.NewString()[:8] + "@example.invalid"
	b := "c2fix2-cw-b-" + uuid.NewString()[:8] + "@example.invalid"
	id := w.adminSetUser(a)
	if st := w.putEmail(id, b); st != http.StatusOK {
		t.Fatalf("change = %d", st)
	}
	u, err := w.repos.User.GetByID(w.ctx, uuid.MustParse(id))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	via := domain.EmailVerifiedViaEmailLink
	_, err = w.repos.User.Update(w.ctx, u.ID, u.OrganizationID, repository.UpdateUserOptions{EmailVerifiedVia: &via, RequireEmail: &a})
	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("write for the old address = %v; want domain.ErrUserNotFound", err)
	}
	if _, got := w.proofRow(id); got == domain.EmailVerifiedViaEmailLink {
		t.Errorf("the write for the old address landed")
	}
	if _, err := w.repos.User.Update(w.ctx, u.ID, u.OrganizationID, repository.UpdateUserOptions{EmailVerifiedVia: &via, RequireEmail: &b}); err != nil {
		t.Fatalf("write for the current address: %v", err)
	}
	if _, got := w.proofRow(id); got != domain.EmailVerifiedViaEmailLink {
		t.Errorf("the write for the current address did not land (via %q)", got)
	}
}

// F3: a padded address on the administrator's PUT is a plain 400, and the
// stored address stays.
func TestE2E_OSS_C2_PaddedAddressIsABadRequest(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	a := "c2fix2-pad-a-" + uuid.NewString()[:8] + "@example.invalid"
	id := w.adminSetUser(a)
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, `{"email":" c2fix2-pad-b-`+uuid.NewString()[:8]+`@example.invalid "}`)
	if st != http.StatusBadRequest {
		t.Errorf("PUT with a padded address = %d %v; want 400", st, m["error"])
	}
	if email, _ := w.proofRow(id); email != a {
		t.Errorf("the stored address changed")
	}
}

// F2: the public resend answers the same plain 200 for the site_admin's
// address and sends nothing; for an ordinary unproven user it still sends.
func TestE2E_OSS_C2_PublicResendSkipsSiteAdmin(t *testing.T) {
	addr, mails := startInviteFakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	w := startInviteEngine(t, map[string]string{
		"UI":                                     inviteUIBase,
		"IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_SMTP_HOST":                 host,
		"IDENTUUM_IDP_SMTP_PORT":                 port,
		"IDENTUUM_IDP_SMTP_FROM":                 "no-reply@idp.test",
		"IDENTUUM_IDP_SMTP_ALLOW_INSECURE":       "true",
	})
	var siteEmail string
	if err := w.pool.QueryRow(w.ctx, `SELECT email FROM users WHERE id = $1`, w.ids["site"]).Scan(&siteEmail); err != nil {
		t.Fatalf("site_admin address: %v", err)
	}
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/resend-verification", `{"email":"`+siteEmail+`"}`)
	unknown, um, _ := w.call("", http.MethodPost, "/api/v1/auth/resend-verification", `{"email":"c2fix2-nobody-`+uuid.NewString()[:8]+`@example.invalid"}`)
	if st != http.StatusOK || st != unknown || m["message"] != um["message"] {
		t.Errorf("site_admin resend = %d %v; want the plain answer an unknown address gets (%d %v)", st, m["message"], unknown, um["message"])
	}
	select {
	case <-mails:
		t.Errorf("a verification mail was sent for the site_admin's reserved address")
	case <-time.After(3 * time.Second):
	}

	// Control: the same route still mails an ordinary unproven user. (The
	// fake server takes one connection, so a site_admin mail above makes this
	// fail too.)
	user := "c2fix2-resend-" + uuid.NewString()[:8] + "@example.invalid"
	w.adminSetUser(user)
	if st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/resend-verification", `{"email":"`+user+`"}`); st != http.StatusOK {
		t.Fatalf("resend for an ordinary user = %d", st)
	}
	select {
	case got := <-mails:
		if !strings.Contains(strings.ToLower(got.rcpt), strings.ToLower(user)) {
			t.Errorf("the control mail is not addressed to the ordinary user")
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no mail for an ordinary unproven user (the control)")
	}
}
