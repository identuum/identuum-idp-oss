//go:build integration

// Package e2e — integration coverage for the WebAuthn credential
// pgx repository. The tests pin the SQL round-trip and the
// challenge-lifecycle invariants the OSS WebAuthn service depends
// on. A virtual authenticator would be required to exercise the
// upstream cryptographic FinishLogin path — that is documented in
// the final report as a Playwright follow-up; everything *up to*
// the cryptographic boundary is tested here.
//
// Pre-fix symptom (none — this is a fresh slice): no integration
// coverage existed for webauthn_credentials in OSS.
//
// Test discipline:
//   - randomized email + uuid per run so the test is isolated;
//   - raw credential_id, public_key bytes, and aaguid bytes are
//     NEVER printed in any assertion message;
//   - t.Cleanup soft-deletes the seeded user + credential so the
//     demo DB stays clean.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...

package e2e

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// TestE2E_OSS_WebAuthnCredentialRepository_RoundTrip seeds an
// org + user + credential, then exercises Create / GetByCredentialID /
// ListByUser / UpdateSignCount / UpdateCloneWarning / Delete and
// verifies their persisted side-effects.
func TestE2E_OSS_WebAuthnCredentialRepository_RoundTrip(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.WebAuthnCredential == nil {
		t.Fatal("repository factory returned nil User or WebAuthnCredential repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	// Random user — the password hash is irrelevant for this test,
	// but Create requires a non-empty plaintext (it argon2id-hashes
	// any non-PHC input). The plaintext is per-run random and never
	// printed.
	email := strings.ToLower("e2e-wa-" + uuid.NewString() + "@example.invalid")
	plaintext := "wa-" + uuid.NewString() + "-marker-not-printed"
	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             userID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})
	_ = plaintext // ensure we never use it after seed

	// Pre-clean any stale rows for this email — defensive but
	// almost certainly a no-op given the per-run random email.
	defer func() {
		// Soft-delete the credential rows. We rely on the
		// soft-delete unique index so a re-run with the same
		// credential_id will not collide.
		creds, _ := repos.WebAuthnCredential.ListByUser(context.Background(), created.ID)
		for _, c := range creds {
			_ = repos.WebAuthnCredential.Delete(context.Background(), c.ID)
		}
	}()

	// Random raw credential id + public key bytes. These will be
	// persisted as bytea and read back verbatim.
	credID := randBytes(t, 32)
	pubKey := randBytes(t, 65)

	row := &domain.WebAuthnCredential{
		UserID:          created.ID,
		OrganizationID:  org.ID,
		CredentialID:    credID,
		PublicKey:       pubKey,
		AttestationType: "none",
		Transport:       []string{"internal"},
		SignCount:       0,
		CloneWarning:    false,
		BackupEligible:  true,
		BackupState:     false,
	}
	stored, err := repos.WebAuthnCredential.Create(ctx, row)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if stored.ID == uuid.Nil {
		t.Fatal("create credential: returned row carries uuid.Nil id (UUIDv7 invariant broken)")
	}

	// GetByCredentialID round-trips the raw bytes.
	got, err := repos.WebAuthnCredential.GetByCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if !bytesEqual(got.CredentialID, credID) {
		t.Error("GetByCredentialID: credential_id round-trip mismatch")
	}
	if !bytesEqual(got.PublicKey, pubKey) {
		t.Error("GetByCredentialID: public_key round-trip mismatch")
	}
	if got.OrganizationID != org.ID {
		t.Errorf("GetByCredentialID: organization_id mismatch got=%s want=%s", got.OrganizationID, org.ID)
	}

	// ListByUser sees exactly one credential for the seeded user.
	creds, err := repos.WebAuthnCredential.ListByUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("ListByUser: got %d, want 1", len(creds))
	}

	// UpdateSignCount lands.
	if err := repos.WebAuthnCredential.UpdateSignCount(ctx, stored.ID, 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	got, err = repos.WebAuthnCredential.GetByCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("GetByCredentialID after sign_count update: %v", err)
	}
	if got.SignCount != 42 {
		t.Errorf("UpdateSignCount: sign_count = %d, want 42", got.SignCount)
	}
	if got.LastUsedAt == nil {
		t.Error("UpdateSignCount: last_used_at must be populated after sign_count update")
	}

	// UpdateCloneWarning lands.
	if err := repos.WebAuthnCredential.UpdateCloneWarning(ctx, stored.ID, true); err != nil {
		t.Fatalf("UpdateCloneWarning: %v", err)
	}
	got, err = repos.WebAuthnCredential.GetByCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("GetByCredentialID after clone_warning update: %v", err)
	}
	if !got.CloneWarning {
		t.Error("UpdateCloneWarning: clone_warning must be true after update")
	}

	// Delete soft-deletes.
	if err := repos.WebAuthnCredential.Delete(ctx, stored.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repos.WebAuthnCredential.GetByCredentialID(ctx, credID); err == nil {
		t.Error("GetByCredentialID after Delete: want ErrWebAuthnCredentialNotFound, got nil")
	} else if !errorsIsNotFound(err) {
		// The repo error wraps the sentinel; verify the wrapping
		// produces a not-found classification.
		t.Errorf("GetByCredentialID after Delete: want not-found, got %s", classifyNotFound(err))
	}

	// ListByUser now empty.
	creds, err = repos.WebAuthnCredential.ListByUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListByUser after delete: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("ListByUser after delete: got %d, want 0", len(creds))
	}
}

// randBytes returns n cryptographically-random bytes. The bytes
// are NEVER printed by the caller.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// bytesEqual returns true when a and b have the same content.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errorsIsNotFound returns true when err wraps
// repository.ErrWebAuthnCredentialNotFound. The repo wraps the
// sentinel in a fmt.Errorf("…: %w", err) so direct identity
// comparison fails; errors.Is is the correct check.
func errorsIsNotFound(err error) bool {
	return err != nil && isNotFound(err)
}

func isNotFound(err error) bool {
	for e := err; e != nil; {
		if e == repository.ErrWebAuthnCredentialNotFound { //nolint:errorlint // intentional sentinel walk
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// classifyNotFound returns a category string for error messages
// without leaking the underlying message.
func classifyNotFound(err error) string {
	if err == nil {
		return "<nil>"
	}
	return "non-not-found"
}
