package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-FIN-1 (D-017): a user created with an admin-set password proves it and
// is answered the change step FIRST — before MFA enrolment or verification,
// before any session — whatever the MFA policy. Before this slice the flag
// collapsed to invalid_credentials, so such a user could never sign in.
func TestLogin_RequiredPasswordChangeComesFirst(t *testing.T) {
	required := "required"
	for _, tt := range []struct {
		name string
		user domain.User
	}{
		{"org_user, optional MFA", domain.User{Role: domain.RoleOrgUser}},
		{"org_user, MFA required, not enrolled", domain.User{Role: domain.RoleOrgUser, MFAPolicy: &required}},
		{"org_admin (MFA always required), not enrolled", domain.User{Role: domain.RoleOrgAdmin}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc, users := newLoginHarness(t)
			u := tt.user
			u.ID = uuid.New()
			u.Email = "set-by-admin@example.com"
			u.PasswordHash = hashPwd(t, "admin-set")
			u.EmailVerified = true
			u.RequiresPasswordChange = true
			users.byEmail[u.Email] = []*domain.User{&u}
			res, err := svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "admin-set"})
			if !errors.Is(err, ErrLoginPasswordChangeRequired) {
				t.Fatalf("err = %v; want ErrLoginPasswordChangeRequired", err)
			}
			if res == nil || res.User == nil || res.User.ID != u.ID || res.Session != nil || res.RefreshToken != "" {
				t.Errorf("result = %+v; want the user and no session or token", res)
			}
		})
	}
}

// A wrong password never reaches the change step.
func TestLogin_RequiredPasswordChangeNeedsThePassword(t *testing.T) {
	svc, users := newLoginHarness(t)
	u := &domain.User{ID: uuid.New(), Email: "set-by-admin@example.com", PasswordHash: hashPwd(t, "admin-set"), EmailVerified: true, RequiresPasswordChange: true, Role: domain.RoleOrgUser}
	users.byEmail[u.Email] = []*domain.User{u}
	if _, err := svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "wrong"}); !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v; want ErrLoginInvalidCredentials", err)
	}
}

// OSS-G8-PASSKEY-MFA-CARRYOVER: the change step reads the passkey proof from
// the stored row's kind only. An ordinary handle carries none, a proof handle
// carries it for its own user, and neither an MFA handle nor a spent or
// expired proof handle redeems.
func TestPeekPasswordChange_ProofComesFromTheRowKind(t *testing.T) {
	ctx := context.Background()
	svc, pending, _, user := newEnrollSvc(t)
	plain, err := svc.CreatePending(ctx, user, domain.MFAPendingKindPasswordChange, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.PeekPasswordChange(ctx, plain.ID, ""); err != nil || got.UserID != user.ID || !got.RememberMe || got.PasskeyVerified {
		t.Errorf("Peek(password_change) = %+v, %v; want the user, remember-me and no proof", got, err)
	}
	proof, secret, err := svc.CreatePasskeyPasswordChange(ctx, user, true)
	if err != nil || proof.Kind != domain.MFAPendingKindPasswordChangePasskeyUV {
		t.Fatalf("CreatePasskeyPasswordChange = %v, %v", proof, err)
	}
	if got, err := svc.PeekPasswordChange(ctx, proof.ID, secret); err != nil || got.UserID != user.ID || !got.RememberMe || !got.PasskeyVerified {
		t.Errorf("Peek(proof, its client) = %+v, %v; want the user, remember-me and the proof", got, err)
	}
	for _, kind := range []domain.MFAPendingKind{domain.MFAPendingKindEnroll, domain.MFAPendingKindVerify} {
		row, err := svc.CreatePending(ctx, user, kind, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := svc.PeekPasswordChange(ctx, row.ID, ""); !errors.Is(err, ErrMFAEnrollmentInvalid) || got.PasskeyVerified {
			t.Errorf("Peek(%s handle) = %+v, %v; want ErrMFAEnrollmentInvalid", kind, got, err)
		}
	}
	spent, spentSecret, _ := svc.CreatePasskeyPasswordChange(ctx, user, false)
	if err := svc.ConsumePasswordChange(ctx, spent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PeekPasswordChange(ctx, spent.ID, spentSecret); !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Errorf("Peek(spent proof) err = %v; want ErrMFAEnrollmentAlreadyConsumed", err)
	}
	if err := svc.ConsumePasswordChange(ctx, spent.ID); !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Errorf("second consume err = %v; want ErrMFAEnrollmentAlreadyConsumed", err)
	}
	expired, expiredSecret, _ := svc.CreatePasskeyPasswordChange(ctx, user, false)
	pending.rows[expired.ID].ExpiresAt = svc.now().Add(-time.Second)
	if _, err := svc.PeekPasswordChange(ctx, expired.ID, expiredSecret); !errors.Is(err, ErrMFAEnrollmentExpired) {
		t.Errorf("Peek(expired proof) err = %v; want ErrMFAEnrollmentExpired", err)
	}
}

// OSS-G8-PASSKEY-MFA-R2 (F1): a passkey proof is minted only bound to its
// client, stores the secret's hash and not the secret, and redeems only with
// that client's secret; an unbound proof cannot be minted at all.
func TestPeekPasswordChange_ProofIsBoundToItsClient(t *testing.T) {
	ctx := context.Background()
	svc, _, _, user := newEnrollSvc(t)
	if _, err := svc.CreatePending(ctx, user, domain.MFAPendingKindPasswordChangePasskeyUV, false); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("CreatePending(passkey proof) err = %v; want ErrMFAEnrollmentInvalid (unbound proof)", err)
	}
	a, secretA, err := svc.CreatePasskeyPasswordChange(ctx, user, false)
	if err != nil || len(secretA) < 43 {
		t.Fatalf("CreatePasskeyPasswordChange = %v, secret length %d; want >= 43 (32 bytes)", err, len(secretA))
	}
	_, secretB, _ := svc.CreatePasskeyPasswordChange(ctx, user, false)
	sum := sha256.Sum256([]byte(secretA))
	if !bytes.Equal(a.ClientBinding, sum[:]) || bytes.Contains(a.ClientBinding, []byte(secretA)) {
		t.Errorf("the row stores %d binding bytes; want exactly the secret's SHA-256", len(a.ClientBinding))
	}
	last := "A"
	if strings.HasSuffix(secretA, "A") {
		last = "B"
	}
	for label, presented := range map[string]string{"no secret": "", "another flow's secret": secretB, "a near miss": secretA[:len(secretA)-1] + last} {
		if got, err := svc.PeekPasswordChange(ctx, a.ID, presented); !errors.Is(err, ErrMFAEnrollmentInvalid) || got.PasskeyVerified || got.UserID != uuid.Nil {
			t.Errorf("Peek(proof, %s) = %+v, %v; want ErrMFAEnrollmentInvalid and nothing", label, got, err)
		}
	}
	if got, err := svc.PeekPasswordChange(ctx, a.ID, secretA); err != nil || !got.PasskeyVerified {
		t.Errorf("Peek(proof, its own secret) after refusals = %+v, %v; want the proof", got, err)
	}
}
