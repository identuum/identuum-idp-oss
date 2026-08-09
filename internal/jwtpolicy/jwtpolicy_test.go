package jwtpolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signEdDSA mints an EdDSA JWT with the given kid + claims.
func signEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func baseClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "https://issuer.example",
		"sub": "user-1",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
}

// The shared policy: happy path returns claims; the key resolver receives the
// kid + alg and its returned key verifies the signature.
func TestParse_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tokenStr := signEdDSA(t, priv, "kid-1", baseClaims())

	var gotKID, gotAlg string
	claims, err := Parse(tokenStr, []string{"EdDSA"}, func(a string) bool { return a == "EdDSA" },
		func(kid, alg string) (any, error) { gotKID, gotAlg = kid, alg; return pub, nil }, Required{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if gotKID != "kid-1" || gotAlg != "EdDSA" {
		t.Errorf("resolveKey got (kid=%q, alg=%q), want (kid-1, EdDSA)", gotKID, gotAlg)
	}
	if iss, _ := claims["iss"].(string); iss != "https://issuer.example" {
		t.Errorf("claims not returned: %v", claims)
	}
}

// alg=none, empty alg, a non-allowlisted alg, a missing kid, a resolver error,
// and an alg outside allowedMethods are ALL rejected as ErrParse.
func TestParse_Rejections(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allow := func(a string) bool { return a == "EdDSA" }
	resolve := func(_, _ string) (any, error) { return pub, nil }

	t.Run("alg=none", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
		tok.Header["kid"] = "kid-1"
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("alg=none: err = %v, want ErrParse", err)
		}
	})
	t.Run("non-allowlisted alg (predicate rejects)", func(t *testing.T) {
		s := signEdDSA(t, priv, "kid-1", baseClaims())
		// Predicate says no even though the token is EdDSA and it's in allowedMethods.
		if _, err := Parse(s, []string{"EdDSA"}, func(string) bool { return false }, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("predicate-rejected alg: err = %v, want ErrParse", err)
		}
	})
	t.Run("alg outside allowedMethods (WithValidMethods)", func(t *testing.T) {
		s := signEdDSA(t, priv, "kid-1", baseClaims())
		// Predicate allows EdDSA but WithValidMethods does not list it.
		if _, err := Parse(s, []string{"ES256"}, allow, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("alg outside allowedMethods: err = %v, want ErrParse", err)
		}
	})
	t.Run("missing kid", func(t *testing.T) {
		s := signEdDSA(t, priv, "", baseClaims()) // no kid header
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("missing kid: err = %v, want ErrParse", err)
		}
	})
	t.Run("resolver error propagates", func(t *testing.T) {
		s := signEdDSA(t, priv, "kid-1", baseClaims())
		failResolve := func(_, _ string) (any, error) { return nil, errors.New("no such key") }
		if _, err := Parse(s, []string{"EdDSA"}, allow, failResolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("resolver error: err = %v, want ErrParse", err)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		s := signEdDSA(t, priv, "kid-1", c)
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("expired: err = %v, want ErrParse", err)
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		_, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
		s := signEdDSA(t, foreignPriv, "kid-1", baseClaims()) // signed by a different key
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); !errors.Is(err, ErrParse) {
			t.Errorf("foreign signature: err = %v, want ErrParse", err)
		}
	})
}

// Required makes exp/sub MANDATORY (not merely valid-if-present). A token that
// OMITS exp or sub passes with Required{} but is rejected once the caller
// requires them — the P1-1 fix. The two are independent so each caller can pick
// its own set.
func TestParse_RequiredClaims(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allow := func(a string) bool { return a == "EdDSA" }
	resolve := func(_, _ string) (any, error) { return pub, nil }

	sign := func(mutate func(jwt.MapClaims)) string {
		c := baseClaims()
		if mutate != nil {
			mutate(c)
		}
		return signEdDSA(t, priv, "kid-1", c)
	}

	t.Run("no exp: accepted when not required, rejected when required", func(t *testing.T) {
		s := sign(func(c jwt.MapClaims) { delete(c, "exp") })
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); err != nil {
			t.Errorf("no-exp with Required{}: err = %v, want nil", err)
		}
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{Expiration: true}); !errors.Is(err, ErrParse) {
			t.Errorf("no-exp with Expiration required: err = %v, want ErrParse", err)
		}
	})
	t.Run("absent sub: accepted when not required, rejected when required", func(t *testing.T) {
		s := sign(func(c jwt.MapClaims) { delete(c, "sub") })
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{}); err != nil {
			t.Errorf("absent-sub with Required{}: err = %v, want nil", err)
		}
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{Subject: true}); !errors.Is(err, ErrParse) {
			t.Errorf("absent-sub with Subject required: err = %v, want ErrParse", err)
		}
	})
	t.Run("empty sub is rejected when Subject required", func(t *testing.T) {
		s := sign(func(c jwt.MapClaims) { c["sub"] = "" })
		if _, err := Parse(s, []string{"EdDSA"}, allow, resolve, Required{Subject: true}); !errors.Is(err, ErrParse) {
			t.Errorf("empty-sub with Subject required: err = %v, want ErrParse", err)
		}
	})
}
