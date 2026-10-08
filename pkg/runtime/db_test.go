package runtime_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

// testEncryptionKey is the throwaway at-rest key every DB-backed runtime test
// in this module uses.
const testEncryptionKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// migratedTestDSN returns the test database URL, migrated, and sets the
// environment a test runtime needs; it skips when no test database is set.
func migratedTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping a DB-backed runtime test")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := postgres.RunMigrations(context.Background(), db); err != nil {
		t.Fatalf("migrate the test database: %v", err)
	}
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", testEncryptionKey)
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	return dsn
}

// seedSigningKey adds an active EdDSA signing key with a unique kid and
// removes it when the test ends; the runtime trusts tokens it signs.
func seedSigningKey(t *testing.T, dsn string) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := postgres.NewPool(context.Background(), dsn, nil)
	if err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	t.Cleanup(pool.Close)
	cipher, err := crypto.NewCryptoService(testEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	kid := "seam2-" + uuid.NewString()
	if err := postgres.NewPgxRepositories(pool, cipher).Key.CreateSigningKey(context.Background(), &domain.SigningKey{
		ID: uuid.New(), KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, State: domain.KeyStateActive,
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}); err != nil {
		t.Fatalf("seed signing key: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM signing_keys WHERE kid = $1`, kid); err != nil {
			t.Errorf("remove the seeded signing key: %v", err)
		}
	})
	return kid, priv
}

// signToken signs claims with the seeded key. The token stays in the test
// process; nothing prints it.
func signToken(t *testing.T, kid string, priv ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
