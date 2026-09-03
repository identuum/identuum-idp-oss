package service

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// DPoP (RFC 9449) proof verification for the TOKEN ENDPOINT (AYGHU-3).
//
// A proof presented to the token endpoint is a JWS with typ "dpop+jwt", an
// asymmetric alg from the repository's registered allow-list, the PUBLIC
// key in the `jwk` header, and exactly the claims htm, htu, iat, jti. There
// is no access token yet, so `ath` MUST be absent; this server issues no
// DPoP nonces, so `nonce` MUST be absent. Anything else fails closed. The
// verifier never logs the proof; every refusal surfaces as
// ErrDPoPProofInvalid so a presenter cannot probe which check failed.

const (
	dpopProofTyp        = "dpop+jwt"
	dpopProofClockSkew  = 60 * time.Second
	dpopProofMaxJTILen  = 256
	dpopProofMaxProofLn = 8 * 1024
)

var (
	// ErrDPoPProofRequired — the request needs sender constraint (agent
	// communication) and carried no DPoP header. The answer is a refusal,
	// never a Bearer token.
	ErrDPoPProofRequired = errors.New("service: DPoP proof required")
	// ErrDPoPProofInvalid — the proof did not verify (shape, alg, key,
	// signature, htm/htu, iat window, jti, thumbprint).
	ErrDPoPProofInvalid = errors.New("service: DPoP proof invalid")
	// ErrDPoPProofReplayed — the proof's jti was already used with this key.
	ErrDPoPProofReplayed = errors.New("service: DPoP proof replayed")
)

// DPoPProof is the verified content of a token-endpoint proof.
type DPoPProof struct {
	JTI       string
	HTM       string
	HTU       string
	IssuedAt  time.Time
	JKT       string
	PublicKey crypto.PublicKey
}

// JWKThumbprint computes the RFC 7638 thumbprint of a public JWK: the
// required members of the key type in lexicographic order, no whitespace,
// SHA-256, base64url without padding.
func JWKThumbprint(jwk map[string]any) (string, error) {
	str := func(k string) (string, error) {
		v, ok := jwk[k].(string)
		if !ok || v == "" {
			return "", fmt.Errorf("jwk member %q missing", k)
		}
		return v, nil
	}
	var canonical any
	switch kty, _ := jwk["kty"].(string); kty {
	case "RSA":
		e, err := str("e")
		if err != nil {
			return "", err
		}
		n, err := str("n")
		if err != nil {
			return "", err
		}
		canonical = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{e, "RSA", n}
	case "EC":
		crv, err := str("crv")
		if err != nil {
			return "", err
		}
		x, err := str("x")
		if err != nil {
			return "", err
		}
		y, err := str("y")
		if err != nil {
			return "", err
		}
		canonical = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{crv, "EC", x, y}
	case "OKP":
		crv, err := str("crv")
		if err != nil {
			return "", err
		}
		x, err := str("x")
		if err != nil {
			return "", err
		}
		canonical = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{crv, "OKP", x}
	default:
		return "", fmt.Errorf("jwk kty %q not supported", kty)
	}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// normalizeDPoPHTU reduces a URI to the RFC 9449 §4.3 comparison form:
// scheme and host lowercased, query and fragment removed, default ports
// dropped, an empty path read as "/".
func normalizeDPoPHTU(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("htu is not an absolute URI")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if (scheme == "https" && strings.HasSuffix(host, ":443")) || (scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// VerifyDPoPTokenEndpointProof verifies proof for an HTTP request with
// method htm to the token endpoint expectedHTU at time now. The returned
// JKT is the RFC 7638 thumbprint of the proof's public key; the caller
// binds it to the participant's enrolled thumbprint and marks the jti.
func VerifyDPoPTokenEndpointProof(proof, htm, expectedHTU string, now time.Time) (*DPoPProof, error) {
	proof = strings.TrimSpace(proof)
	if proof == "" {
		return nil, ErrDPoPProofRequired
	}
	if len(proof) > dpopProofMaxProofLn || strings.Count(proof, ".") != 2 {
		return nil, fmt.Errorf("%w: shape", ErrDPoPProofInvalid)
	}
	wantHTU, err := normalizeDPoPHTU(expectedHTU)
	if err != nil {
		return nil, fmt.Errorf("%w: server token endpoint: %v", ErrDPoPProofInvalid, err)
	}

	// 1. Unverified parse: header only, then decide the key from it.
	var raw jwt.MapClaims
	unverified, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(proof, &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse", ErrDPoPProofInvalid)
	}
	if typ, _ := unverified.Header["typ"].(string); typ != dpopProofTyp {
		return nil, fmt.Errorf("%w: typ", ErrDPoPProofInvalid)
	}
	alg, _ := unverified.Header["alg"].(string)
	if _, ok := domain.PrivateKeyJWTSigningAlgorithms[alg]; !ok {
		return nil, fmt.Errorf("%w: alg", ErrDPoPProofInvalid)
	}
	jwkMap, ok := unverified.Header["jwk"].(map[string]any)
	if !ok || len(jwkMap) == 0 {
		return nil, fmt.Errorf("%w: jwk header", ErrDPoPProofInvalid)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, leaked := jwkMap[private]; leaked {
			return nil, fmt.Errorf("%w: jwk carries private material", ErrDPoPProofInvalid)
		}
	}
	pub, err := clientAssertionPublicKeyFromJWK(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk", ErrDPoPProofInvalid)
	}
	jkt, err := JWKThumbprint(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk thumbprint", ErrDPoPProofInvalid)
	}

	// 2. Signature with the header key and exactly the declared alg.
	verified := jwt.MapClaims{}
	if _, err := jwt.NewParser(jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation()).
		ParseWithClaims(proof, &verified, func(t *jwt.Token) (any, error) {
			if hdrAlg, _ := t.Header["alg"].(string); hdrAlg != alg {
				return nil, errors.New("alg changed during parse")
			}
			return pub, nil
		}); err != nil {
		return nil, fmt.Errorf("%w: signature", ErrDPoPProofInvalid)
	}

	// 3. Claims: exactly htm, htu, iat, jti. ath and nonce do not belong
	// to a token-endpoint proof on this server; anything unknown fails closed.
	for k := range verified {
		switch k {
		case "htm", "htu", "iat", "jti":
		default:
			return nil, fmt.Errorf("%w: claim %q not allowed", ErrDPoPProofInvalid, k)
		}
	}
	gotHTM, _ := verified["htm"].(string)
	if gotHTM == "" || gotHTM != strings.ToUpper(strings.TrimSpace(htm)) {
		return nil, fmt.Errorf("%w: htm", ErrDPoPProofInvalid)
	}
	gotHTU, _ := verified["htu"].(string)
	normHTU, err := normalizeDPoPHTU(gotHTU)
	if err != nil || normHTU != wantHTU {
		return nil, fmt.Errorf("%w: htu", ErrDPoPProofInvalid)
	}
	iatNum, ok := verified["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: iat", ErrDPoPProofInvalid)
	}
	iat := time.Unix(int64(iatNum), 0)
	if delta := now.Sub(iat); delta < -dpopProofClockSkew || delta > dpopProofClockSkew {
		return nil, fmt.Errorf("%w: iat window", ErrDPoPProofInvalid)
	}
	jti, _ := verified["jti"].(string)
	if jti == "" || len(jti) > dpopProofMaxJTILen {
		return nil, fmt.Errorf("%w: jti", ErrDPoPProofInvalid)
	}
	return &DPoPProof{JTI: jti, HTM: gotHTM, HTU: normHTU, IssuedAt: iat, JKT: jkt, PublicKey: pub}, nil
}

// DPoPSigningAlgValuesSupported is the RFC 9449 §5.1 discovery value: the
// asymmetric JWS algorithms a token-endpoint DPoP proof may use here, in
// stable order.
func DPoPSigningAlgValuesSupported() []string {
	out := make([]string, 0, len(domain.PrivateKeyJWTSigningAlgorithms))
	for alg := range domain.PrivateKeyJWTSigningAlgorithms {
		out = append(out, alg)
	}
	sort.Strings(out)
	return out
}

// DPoPThumbprintMatches compares two RFC 7638 thumbprints in constant time.
func DPoPThumbprintMatches(got, enrolled string) bool {
	if got == "" || enrolled == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(enrolled)) == 1
}
