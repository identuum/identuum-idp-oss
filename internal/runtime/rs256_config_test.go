package runtime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestAdvertiseRS256_InvalidConfigurationRefusesConstruction(t *testing.T) {
	for _, raw := range []string{"yes", "enabled", "not-a-boolean"} {
		_, err := New(Config{Addr: "127.0.0.1:0", Getenv: func(name string) string {
			if name == "IDENTUUM_IDP_ADVERTISE_RS256" {
				return raw
			}
			return ""
		}})
		if err == nil || !strings.Contains(err.Error(), "IDENTUUM_IDP_ADVERTISE_RS256") {
			t.Fatal("invalid advertisement setting must refuse runtime construction and name the setting")
		}
		if strings.Contains(err.Error(), raw) {
			t.Fatal("invalid configuration must not echo its value")
		}
	}
}

func TestAdvertiseRS256_Config(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{{"", false}, {"false", false}, {"0", false}, {"true", true}, {"1", true}, {" TRUE ", true}} {
		r, err := New(Config{Addr: "127.0.0.1:0", Getenv: func(name string) string {
			if name == "IDENTUUM_IDP_ADVERTISE_RS256" {
				return tc.raw
			}
			return ""
		}})
		if err != nil || r.cfg.AdvertiseRS256 != tc.want {
			t.Fatalf("boolean configuration did not resolve to %v", tc.want)
		}
	}
	r, err := New(Config{Addr: "127.0.0.1:0", AdvertiseRS256: true, Getenv: func(string) string { return "" }})
	if err != nil || !r.cfg.AdvertiseRS256 {
		t.Fatal("explicit config option not retained")
	}
}

type rs256StartupRepo struct {
	repository.KeyRepository
	keys               []domain.SigningKey
	listCalls          int
	creates            []domain.KeyAlgorithm
	listErr, createErr error
}

func (r *rs256StartupRepo) GetActiveSigningKeys(context.Context) ([]domain.SigningKey, error) {
	r.listCalls++
	return r.keys, r.listErr
}

func (r *rs256StartupRepo) CreateSigningKey(_ context.Context, key *domain.SigningKey) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.creates = append(r.creates, key.Algorithm)
	r.keys = append(r.keys, *key)
	return nil
}

func (r *rs256StartupRepo) CreateSigningKeyUnlessActive(ctx context.Context, key *domain.SigningKey, satisfiedBy []domain.KeyAlgorithm) (bool, error) {
	for _, existing := range r.keys {
		if existing.State == domain.KeyStateActive && existing.PrivateKey != "" && slices.Contains(satisfiedBy, existing.Algorithm) {
			return false, nil
		}
	}
	return r.createErr == nil, r.CreateSigningKey(ctx, key)
}

func TestAdvertiseRS256_StartupKeysetAndSigner(t *testing.T) {
	ctx := context.Background()
	repo := &rs256StartupRepo{}
	keys := service.NewKeyService(repo)
	if _, err := keys.Generate(ctx, service.GenerateKeyOptions{Algorithm: "EdDSA", State: domain.KeyStateActive}); err != nil {
		t.Fatal("seed signing key failed")
	}
	provider := server.RepositoryJWKSProvider{Repo: repo}
	before, err := provider.PublicJWKS(ctx)
	if err != nil {
		t.Fatal("initial JWKS failed")
	}
	beforeBytes, _ := json.Marshal(before)
	repo.creates = nil
	repo.listCalls = 0
	var output bytes.Buffer
	if err := ensureAdvertisedRS256Key(ctx, keys, false, &output); err != nil {
		t.Fatal("default initialization failed")
	}
	if repo.listCalls != 0 || len(repo.creates) != 0 || output.Len() != 0 {
		t.Fatal("default path must not read/mint keys or log RS256")
	}
	after, _ := provider.PublicJWKS(ctx)
	afterBytes, _ := json.Marshal(after)
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("default-off JWKS bytes changed")
	}
	if err := ensureAdvertisedRS256Key(ctx, keys, true, &output); err != nil {
		t.Fatal("option-on initialization failed")
	}
	if !reflect.DeepEqual(repo.creates, []domain.KeyAlgorithm{domain.KeyAlgorithmRS256}) {
		t.Fatal("option-on must mint only missing RSA key beside the default key")
	}
	if strings.Count(output.String(), "RS256 is advertised") != 1 {
		t.Fatal("missing single startup advertisement line")
	}
	if err := ensureAdvertisedRS256Key(ctx, keys, true, &output); err != nil {
		t.Fatal("restart failed")
	}
	if len(repo.creates) != 1 {
		t.Fatal("restart minted a duplicate RSA key")
	}
	jwks, err := provider.PublicJWKS(ctx)
	if err != nil || len(jwks.Keys) != 2 || jwks.Keys[1].Alg != "RS256" || jwks.Keys[1].Kty != "RSA" {
		t.Fatal("JWKS must publish active RSA beside EdDSA")
	}
	idTokens := service.NewIDTokenService(nil, keys, service.IDTokenServiceOptions{Issuer: "https://idp.test"})
	for _, alg := range []string{"", "EdDSA", "RS256"} {
		client := domain.Client{IDTokenSignedResponseAlg: alg}
		response, err := idTokens.Issue(ctx, service.IDTokenInput{User: &domain.User{ID: uuid.New()}, Session: &domain.Session{ID: uuid.New()}, Audience: "test-client", SigningAlg: client.EffectiveIDTokenAlg()})
		if err != nil {
			t.Fatal("ID token issuance failed")
		}
		parsed, _, err := jwt.NewParser().ParseUnverified(response.IDToken, jwt.MapClaims{})
		if err != nil {
			t.Fatal("ID token parse failed")
		}
		want := "EdDSA"
		if alg == "RS256" {
			want = "RS256"
		}
		if parsed.Method.Alg() != want {
			t.Fatalf("signing algorithm got %s want %s", parsed.Method.Alg(), want)
		}
		verified, err := jwt.Parse(response.IDToken, func(token *jwt.Token) (any, error) {
			for _, key := range repo.keys {
				if token.Header["kid"] == key.KID {
					block, _ := pem.Decode([]byte(key.PublicKey))
					if block == nil {
						return nil, errors.New("public key unavailable")
					}
					return x509.ParsePKIXPublicKey(block.Bytes)
				}
			}
			return nil, errors.New("public key not found")
		}, jwt.WithValidMethods([]string{want}), jwt.WithIssuer("https://idp.test"), jwt.WithAudience("test-client"))
		if err != nil || !verified.Valid {
			t.Fatal("startup-generated key did not verify the ID token")
		}
	}
}

func TestAdvertiseRS256_RefusesAStoreThatCannotSerialize(t *testing.T) {
	repo := &rs256StartupRepo{}
	var output bytes.Buffer
	err := ensureAdvertisedRS256Key(context.Background(), service.NewKeyService(struct{ repository.KeyRepository }{repo}), true, &output)
	if err == nil || len(repo.creates) != 0 || output.Len() != 0 {
		t.Fatal("a key store without serialized provisioning must be refused, not raced")
	}
}

func TestAdvertiseRS256_EmptyStoreAndFailures(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		repo *rs256StartupRepo
		fail bool
	}{
		{"fresh", &rs256StartupRepo{}, false},
		{"list failure", &rs256StartupRepo{listErr: errors.New("store unavailable")}, true},
		{"write failure", &rs256StartupRepo{createErr: errors.New("store unavailable")}, true},
		{"rotating RSA", &rs256StartupRepo{keys: []domain.SigningKey{{Algorithm: domain.KeyAlgorithmRS256, State: domain.KeyStateRotating, PrivateKey: "fixture"}}}, false},
		{"RSA without private material", &rs256StartupRepo{keys: []domain.SigningKey{{Algorithm: domain.KeyAlgorithmRS256, State: domain.KeyStateActive}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := ensureAdvertisedRS256Key(ctx, service.NewKeyService(tc.repo), true, &output)
			if (err != nil) != tc.fail {
				t.Fatal("startup error result differs")
			}
			if tc.fail {
				if output.Len() != 0 {
					t.Fatal("failed key initialization claimed advertisement")
				}
				return
			}
			if !reflect.DeepEqual(tc.repo.creates, []domain.KeyAlgorithm{domain.KeyAlgorithmEdDSA, domain.KeyAlgorithmRS256}) {
				t.Fatal("fresh startup must retain an EdDSA default and mint active RSA")
			}
			for _, key := range tc.repo.keys[len(tc.repo.keys)-2:] {
				if key.State != domain.KeyStateActive {
					t.Fatal("new key is not active")
				}
			}
		})
	}
}
