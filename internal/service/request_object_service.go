package service

// request_object_service.go — THE-JAR-REQUEST-OBJECT (2026-09-02): OIDC Core
// §6 / RFC 9101 request objects passed BY VALUE (`request=<JWT>`).
//
// Decisions (owner ruled the last conformance skip closes truthfully):
//
//   - Signed objects are verified against the client's REGISTERED keys
//     (inline `jwks` or `jwks_uri`, the same resolution private_key_jwt
//     uses) with the same asymmetric allow-list
//     (domain.PrivateKeyJWTSigningAlgorithms); HS* and unknown algs are
//     refused — a shared-secret MAC would let anyone who knows the client
//     secret forge "signed" requests.
//   - UNSIGNED objects (alg "none", empty signature segment) are ACCEPTED
//     and advertised. An unsigned object carries no authority a plain
//     query string lacks: every merged value still goes through the same
//     client/redirect_uri/PKCE/scope/claims/acr validation. Refusing them
//     would only keep the conformance module skipping (it drives an
//     alg=none object and treats request_not_supported as a skip).
//   - `request_uri` stays REFUSED (request_uri_not_supported) and discovery
//     says so explicitly — no half state.
//
// Merging (§6.1 / RFC 9101 §5): `client_id` MUST be in the query and, when
// also in the object, MUST match; `response_type` in both MUST match; the
// object's members otherwise SUPERSEDE the query; `request` / `request_uri`
// inside the object are forbidden. If present, `iss` must be the client_id,
// `aud` must name this issuer, `exp` must be in the future, `nbf` must not
// be in the future. Every merged value is a plain string that then feeds
// the SAME parsing the query path uses (AuthorizeRequest → Authorize):
// scope clamping, PKCE, ParseClaimsRequest, acr_values, max_age.
//
// Errors: ErrAuthorizeInvalidClient when the query client_id is unknown
// (direct 400 — no trusted redirect_uri exists); otherwise
// ErrAuthorizeInvalidRequestObject, redirect-safe ONLY when the QUERY
// redirect_uri is registered for that client (the object's redirect_uri
// cannot be trusted until the object verifies).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrAuthorizeInvalidRequestObject — OIDC Core §3.1.2.6 `invalid_request_object`.
var ErrAuthorizeInvalidRequestObject = errors.New("service: authorize invalid_request_object")

// RequestObjectService resolves `request=<JWT>` into merged authorize
// parameters.
type RequestObjectService struct {
	clients AuthorizeClientLookup
	jwks    ClientJWKSFetcher
	issuer  string
	now     func() time.Time
}

// NewRequestObjectService wires the client lookup (keys + redirect_uris),
// the JWKS fetcher for jwks_uri clients (nil → inline jwks only) and this
// OP's issuer (the accepted `aud`).
func NewRequestObjectService(clients AuthorizeClientLookup, jwks ClientJWKSFetcher, issuer string) *RequestObjectService {
	return &RequestObjectService{clients: clients, jwks: jwks, issuer: strings.TrimRight(strings.TrimSpace(issuer), "/"), now: time.Now}
}

// WithClock is for tests.
func (s *RequestObjectService) WithClock(now func() time.Time) *RequestObjectService {
	s.now = now
	return s
}

// RequestObjectSigningAlgValuesSupported is what discovery advertises —
// delegated to the domain (the one source shared with internal/server).
func RequestObjectSigningAlgValuesSupported() []string {
	return domain.RequestObjectSigningAlgValuesSupported()
}

// Resolve returns the merged parameters. redirectSafe reports whether the
// caller may redirect an error to the QUERY redirect_uri (client known and
// that URI registered). When the query carries no `request`, the query is
// returned unchanged.
func (s *RequestObjectService) Resolve(ctx context.Context, query url.Values) (merged url.Values, redirectSafe bool, err error) {
	raw := strings.TrimSpace(query.Get("request"))
	if raw == "" {
		return query, false, nil
	}
	clientID := strings.TrimSpace(query.Get("client_id"))
	if clientID == "" {
		return nil, false, ErrAuthorizeMissingParameters
	}
	client, cerr := s.clients.GetClientByClientID(ctx, clientID)
	if cerr != nil || client == nil {
		return nil, false, ErrAuthorizeInvalidClient
	}
	queryRedirect := strings.TrimSpace(query.Get("redirect_uri"))
	redirectSafe = queryRedirect != "" && client.IsRedirectURIAllowed(queryRedirect)

	claims, err := s.verify(ctx, client, raw)
	if err != nil {
		return nil, redirectSafe, err
	}
	out := url.Values{}
	for k, v := range query {
		if k == "request" || k == "request_uri" {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	for k, v := range claims {
		switch k {
		case "request", "request_uri":
			return nil, redirectSafe, fmt.Errorf("%w: %s inside the request object", ErrAuthorizeInvalidRequestObject, k)
		case "iss", "aud", "exp", "nbf", "iat", "jti":
			continue // validated in verify; not authorize parameters
		}
		str, ok := stringifyClaim(v)
		if !ok {
			return nil, redirectSafe, fmt.Errorf("%w: member %s has an unusable value", ErrAuthorizeInvalidRequestObject, k)
		}
		switch k {
		case "client_id":
			if str != clientID {
				return nil, redirectSafe, fmt.Errorf("%w: client_id in the object differs from the request", ErrAuthorizeInvalidRequestObject)
			}
		case "response_type":
			if q := strings.TrimSpace(query.Get("response_type")); q != "" && q != str {
				return nil, redirectSafe, fmt.Errorf("%w: response_type in the object differs from the request", ErrAuthorizeInvalidRequestObject)
			}
		}
		out.Set(k, str)
	}
	return out, redirectSafe, nil
}

// verify parses the compact JWS, enforces the alg policy and, for signed
// objects, verifies the signature with the client's registered keys.
func (s *RequestObjectService) verify(ctx context.Context, client *domain.Client, raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrAuthorizeInvalidRequestObject)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrAuthorizeInvalidRequestObject)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON", ErrAuthorizeInvalidRequestObject)
	}
	var claims map[string]any
	switch {
	case header.Alg == "none":
		if parts[2] != "" {
			return nil, fmt.Errorf("%w: alg none with a signature", ErrAuthorizeInvalidRequestObject)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w: payload is not base64url", ErrAuthorizeInvalidRequestObject)
		}
		if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
			return nil, fmt.Errorf("%w: payload is not a JSON object", ErrAuthorizeInvalidRequestObject)
		}
	case header.Alg == "":
		return nil, fmt.Errorf("%w: missing alg", ErrAuthorizeInvalidRequestObject)
	case strings.HasPrefix(header.Alg, "HS"):
		return nil, fmt.Errorf("%w: symmetric alg %s is not accepted", ErrAuthorizeInvalidRequestObject, header.Alg)
	default:
		if _, ok := domain.PrivateKeyJWTSigningAlgorithms[header.Alg]; !ok {
			return nil, fmt.Errorf("%w: alg %s is not supported", ErrAuthorizeInvalidRequestObject, header.Alg)
		}
		key, kerr := s.resolveKey(ctx, client, header.Kid)
		if kerr != nil {
			return nil, fmt.Errorf("%w: no registered key verifies this object", ErrAuthorizeInvalidRequestObject)
		}
		mc := jwt.MapClaims{}
		if _, perr := jwt.NewParser(jwt.WithValidMethods([]string{header.Alg}), jwt.WithoutClaimsValidation()).
			ParseWithClaims(raw, &mc, func(*jwt.Token) (any, error) { return key, nil }); perr != nil {
			return nil, fmt.Errorf("%w: signature does not verify", ErrAuthorizeInvalidRequestObject)
		}
		claims = map[string]any(mc)
	}
	// Envelope claims, when present.
	now := s.now()
	if iss, ok := claims["iss"]; ok {
		if str, _ := iss.(string); str != client.ClientID {
			return nil, fmt.Errorf("%w: iss must be the client_id", ErrAuthorizeInvalidRequestObject)
		}
	}
	if aud, ok := claims["aud"]; ok && !audienceContains(aud, s.issuer) {
		return nil, fmt.Errorf("%w: aud must name this issuer", ErrAuthorizeInvalidRequestObject)
	}
	if exp, ok := numericClaim(claims, "exp"); ok && !now.Before(time.Unix(exp, 0)) {
		return nil, fmt.Errorf("%w: expired", ErrAuthorizeInvalidRequestObject)
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Add(time.Minute).Before(time.Unix(nbf, 0)) {
		return nil, fmt.Errorf("%w: not yet valid", ErrAuthorizeInvalidRequestObject)
	}
	return claims, nil
}

func (s *RequestObjectService) resolveKey(ctx context.Context, client *domain.Client, kid string) (any, error) {
	if strings.TrimSpace(client.JWKS) != "" {
		return resolveInlineAssertionJWKSKey(client.JWKS, kid)
	}
	if uri := strings.TrimSpace(client.JWKSUri); uri != "" && s.jwks != nil {
		return s.jwks.Fetch(ctx, uri, kid)
	}
	return nil, errors.New("client has no registered keys")
}

func audienceContains(aud any, issuer string) bool {
	switch v := aud.(type) {
	case string:
		return strings.TrimRight(v, "/") == issuer
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && strings.TrimRight(s, "/") == issuer {
				return true
			}
		}
	}
	return false
}

func numericClaim(claims map[string]any, name string) (int64, bool) {
	v, ok := claims[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// stringifyClaim renders an object member as the wire string the query
// path would have carried: strings as-is, numbers in decimal (max_age),
// booleans as true/false, objects/arrays as JSON (claims).
func stringifyClaim(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case nil:
		return "", false
	case map[string]any, []any:
		b, err := json.Marshal(t)
		return string(b), err == nil
	}
	return "", false
}
