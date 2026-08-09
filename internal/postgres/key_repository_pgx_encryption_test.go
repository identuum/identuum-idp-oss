//go:build integration

// Integration teeth for P3-5: signing_keys.private_key encryption at rest.
//
// Prerequisites:
//   - Set IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) to a
//     Postgres connection string. Migrations are applied automatically.
//   - Tests skip cleanly when neither env var is set.
//
// Safety: no DB URLs or private key material are echoed in failure messages
// (KIDs and prefixes only).
package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func keyEncTestDBURL(t *testing.T) string {
	t.Helper()
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	// FAIL, DO NOT SKIP (CE-DB-PROVISION, 2026-08-02). This file is behind
	// `//go:build integration`; a skip here silently retired the signing-key
	// encryption teeth while the run reported `ok`. Same rule as testDBURL/P2-20.
	t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set; " +
		"the signing-key encryption teeth were requested via -tags integration and require " +
		"a live Postgres DSN. `make integration-test` supplies it automatically (Makefile)")
	return ""
}

func keyEncPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := keyEncTestDBURL(t)
	stdlibDB, err := postgres.OpenStdlibDB(dbURL)
	if err != nil {
		t.Fatalf("open stdlib db (URL redacted): %v", err)
	}
	if _, err := postgres.RunMigrations(context.Background(), stdlibDB); err != nil {
		t.Fatalf("run migrations (URL redacted): %v", err)
	}
	_ = stdlibDB.Close()
	pool, err := postgres.NewPool(context.Background(), dbURL, nil)
	if err != nil {
		t.Fatalf("new pool (URL redacted): %v", err)
	}
	return pool
}

// throwaway 32-byte hex AES key for the test cipher.
const keyEncTestHexKey = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

func genEdDSAPEM(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privPEM, pubPEM
}

func rawPrivateKey(t *testing.T, ctx context.Context, db postgres.DBTX, kid string) string {
	t.Helper()
	var stored string
	if err := db.QueryRow(ctx, `SELECT private_key FROM signing_keys WHERE kid = $1`, kid).Scan(&stored); err != nil {
		t.Fatalf("read raw private_key: %v", err)
	}
	return stored
}

// TestP3_5_RoundTrip is teeth (a): Generate → the raw DB private_key is NOT a
// plaintext PEM and IS a "v2:" ciphertext; GetSigningKeyByKID returns the
// EXACT original PEM; a JWT signed with the returned key verifies under the
// public key. Revert-proof: if CreateSigningKey stored the PEM unencrypted,
// the "not -----BEGIN / is v2:" assertions fail.
func TestP3_5_RoundTrip(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	cipher, _ := crypto.NewCryptoService(keyEncTestHexKey)
	repo := postgres.NewPgxKeyRepository(pool, cipher)

	privPEM, pubPEM := genEdDSAPEM(t)
	kid := "p35-roundtrip-" + uuid.NewString()
	if err := repo.CreateSigningKey(ctx, &domain.SigningKey{
		ID: uuid.New(), KID: kid, Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey: pubPEM, PrivateKey: privPEM, State: domain.KeyStateActive,
	}); err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}

	raw := rawPrivateKey(t, ctx, pool, kid)
	if strings.HasPrefix(raw, "-----BEGIN") {
		t.Errorf("private_key stored as PLAINTEXT PEM at rest (encryption not applied)")
	}
	if !strings.HasPrefix(raw, "v2:") {
		t.Errorf("private_key not a v2 ciphertext at rest: prefix=%.4q", raw)
	}
	// public_key stays plaintext (it is PUBLIC).
	var rawPub string
	if err := pool.QueryRow(ctx, `SELECT public_key FROM signing_keys WHERE kid = $1`, kid).Scan(&rawPub); err != nil {
		t.Fatalf("read public_key: %v", err)
	}
	if !strings.HasPrefix(rawPub, "-----BEGIN") {
		t.Errorf("public_key should remain plaintext PEM; got prefix %.4q", rawPub)
	}

	got, err := repo.GetSigningKeyByKID(ctx, kid)
	if err != nil {
		t.Fatalf("GetSigningKeyByKID: %v", err)
	}
	if got.PrivateKey != privPEM {
		t.Fatalf("decrypted private_key does not match the original PEM")
	}
	assertSignsAndVerifies(t, got.PrivateKey, pubPEM)
}

// TestP3_5_LegacyPassthrough is teeth (b): a raw plaintext-PEM row (pre-P3-5)
// is read back verbatim and signs correctly — no transition regression.
func TestP3_5_LegacyPassthrough(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	cipher, _ := crypto.NewCryptoService(keyEncTestHexKey)
	repo := postgres.NewPgxKeyRepository(pool, cipher)

	privPEM, pubPEM := genEdDSAPEM(t)
	kid := "p35-legacy-" + uuid.NewString()
	// Seed a LEGACY plaintext row directly (bypassing the encrypting writer).
	if _, err := pool.Exec(ctx,
		`INSERT INTO signing_keys (id, kid, algorithm, public_key, private_key, state)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New(), kid, string(domain.KeyAlgorithmEdDSA), pubPEM, privPEM, "active"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	got, err := repo.GetSigningKeyByKID(ctx, kid)
	if err != nil {
		t.Fatalf("GetSigningKeyByKID(legacy): %v", err)
	}
	if got.PrivateKey != privPEM {
		t.Fatalf("legacy plaintext PEM not returned verbatim")
	}
	assertSignsAndVerifies(t, got.PrivateKey, pubPEM)
}

// TestP3_5_ReEncryptSweep is teeth (c): ReEncryptPlaintextKeys converts a
// legacy row to "v2:" ciphertext that still decrypts to the identical PEM; a
// second run re-encrypts zero rows (idempotent).
func TestP3_5_ReEncryptSweep(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	cipher, _ := crypto.NewCryptoService(keyEncTestHexKey)
	repo := postgres.NewPgxKeyRepository(pool, cipher)

	privPEM, pubPEM := genEdDSAPEM(t)
	kid := "p35-sweep-" + uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO signing_keys (id, kid, algorithm, public_key, private_key, state)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New(), kid, string(domain.KeyAlgorithmEdDSA), pubPEM, privPEM, "active"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	n, err := repo.ReEncryptPlaintextKeys(ctx)
	if err != nil {
		t.Fatalf("ReEncryptPlaintextKeys: %v", err)
	}
	if n < 1 {
		t.Fatalf("sweep re-encrypted %d rows, want >= 1", n)
	}
	raw := rawPrivateKey(t, ctx, pool, kid)
	if strings.HasPrefix(raw, "-----BEGIN") || !strings.HasPrefix(raw, "v2:") {
		t.Errorf("swept row not v2 ciphertext: prefix=%.4q", raw)
	}
	got, err := repo.GetSigningKeyByKID(ctx, kid)
	if err != nil || got.PrivateKey != privPEM {
		t.Fatalf("swept row does not decrypt to the identical PEM: err=%v", err)
	}
	// Second run is idempotent: this row is no longer plaintext, so if any
	// rows remain they are OTHER tests' — assert the re-run does not touch
	// THIS row by confirming it stays the same ciphertext.
	rawBefore := rawPrivateKey(t, ctx, pool, kid)
	if _, err := repo.ReEncryptPlaintextKeys(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if rawAfter := rawPrivateKey(t, ctx, pool, kid); rawAfter != rawBefore {
		t.Errorf("idempotent sweep re-touched an already-encrypted row")
	}
}

// TestP3_5_FailClosed is teeth (d): a private_key that is neither a PEM nor
// decryptable makes the getter ERROR (never hands ciphertext/garbage to the
// signer).
func TestP3_5_FailClosed(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	cipher, _ := crypto.NewCryptoService(keyEncTestHexKey)
	repo := postgres.NewPgxKeyRepository(pool, cipher)

	_, pubPEM := genEdDSAPEM(t)
	kid := "p35-garbage-" + uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO signing_keys (id, kid, algorithm, public_key, private_key, state)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New(), kid, string(domain.KeyAlgorithmEdDSA), pubPEM, "not-a-pem-not-a-ciphertext", "active"); err != nil {
		t.Fatalf("seed garbage row: %v", err)
	}
	if _, err := repo.GetSigningKeyByKID(ctx, kid); err == nil {
		t.Errorf("getter accepted a non-PEM, non-decryptable private_key (must fail-closed)")
	}
}

// assertSignsAndVerifies signs a token with the EdDSA private-key PEM and
// verifies it under the public-key PEM.
func assertSignsAndVerifies(t *testing.T, privPEM, pubPEM string) {
	t.Helper()
	privBlock, _ := pem.Decode([]byte(privPEM))
	if privBlock == nil {
		t.Fatalf("returned private key is not a PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key is not ed25519")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"sub": "p35"})
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pubBlock, _ := pem.Decode([]byte(pubPEM))
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).Parse(signed, func(*jwt.Token) (any, error) {
		return pubAny, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("verify under public key: err=%v valid=%v", err, parsed.Valid)
	}
}
