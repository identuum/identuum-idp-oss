package runtime_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	shim "github.com/identuum/identuum-idp-oss/internal/pkg/runtime"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// OSS-SEAM-1 proof 7: the facade serves byte-identical answers. Two runtimes
// share one migrated test database, one data directory and one configuration:
// the BASELINE through internal/pkg/runtime (the path the identuum-idp binary
// serves through, unchanged since ed5954a) and the CANDIDATE through this
// package. Each request of the corpus goes to both, back to back, as raw
// HTTP/1.1 bytes, and status line, ORDERED headers and body bytes must be
// equal. The request id is fixed by the request (X-Request-Id). One field
// cannot be fixed and is compared by its constraint only: the Date header
// (both must parse as an HTTP date) — that one field is a semantic proof. Nothing
// of a response is printed; a difference names the request and the part.
func TestRuntime_FacadeAnswersByteIdentical(t *testing.T) {
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping the byte-identity comparison")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	if _, err := postgres.RunMigrations(context.Background(), db); err != nil {
		t.Fatalf("migrate the test database: %v", err)
	}
	_ = db.Close()
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	dataDir := t.TempDir()
	stop := func(name string, f func(context.Context) error) {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := f(ctx); err != nil {
				t.Errorf("%s Shutdown: %v", name, err)
			}
		})
	}

	base, err := shim.New(shim.Config{Addr: "127.0.0.1:0", Issuer: "http://localhost:7113", JWKSDBURL: dsn,
		Version: "seam1-identity", DataDir: dataDir, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Start(context.Background()); err != nil {
		t.Fatalf("baseline Start: %v", err)
	}
	stop("baseline", base.Shutdown)
	cand, err := runtime.New(runtime.Options{Addr: "127.0.0.1:0", Issuer: "http://localhost:7113", DatabaseURL: dsn,
		Version: "seam1-identity", DataDir: dataDir, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := cand.Start(context.Background()); err != nil {
		t.Fatalf("candidate Start: %v", err)
	}
	stop("candidate", cand.Shutdown)

	// The authorize and token endpoints are the ones discovery advertises.
	disco := rawRequest(t, base.Addr(), http.MethodGet, "/.well-known/openid-configuration", nil, "")
	var d struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	discoBody := disco.body
	for _, h := range disco.headers {
		if strings.EqualFold(h, "Transfer-Encoding: chunked") {
			discoBody, _ = io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(disco.body)))
		}
	}
	if err := json.Unmarshal(discoBody, &d); err != nil || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		t.Fatalf("discovery names no authorize/token endpoint (status %s)", disco.status)
	}
	authz, tok := pathOf(t, d.AuthorizationEndpoint), pathOf(t, d.TokenEndpoint)
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	basic := map[string]string{"Content-Type": "application/x-www-form-urlencoded",
		"Authorization": "Basic dW5rbm93bi1jbGllbnQ6bm90LXRoZS1zZWNyZXQ="} // unknown-client:not-the-secret
	bogus := map[string]string{"Authorization": "Bearer not-a-token"}
	corpus := []struct {
		name, method, path string
		headers            map[string]string
		body               string
	}{
		{"discovery", http.MethodGet, "/.well-known/openid-configuration", nil, ""},
		{"jwks", http.MethodGet, "/.well-known/jwks.json", nil, ""},
		{"component", http.MethodGet, "/api/v1/component", nil, ""},
		{"authorize with no parameters", http.MethodGet, authz, nil, ""},
		{"authorize for an unknown client", http.MethodGet, authz + "?response_type=code&client_id=unknown-client" +
			"&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb&scope=openid&state=s1", nil, ""},
		{"token with no grant", http.MethodPost, tok, form, ""},
		{"token client_credentials without client auth", http.MethodPost, tok, form, "grant_type=client_credentials"},
		{"token for an unknown client", http.MethodPost, tok, basic, "grant_type=authorization_code&code=x" +
			"&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb"},
		{"tenant users without a principal", http.MethodGet, "/api/v1/users", nil, ""},
		{"tenant organization with a bogus bearer", http.MethodGet,
			"/api/v1/organizations/00000000-0000-7000-8000-000000000001", bogus, ""},
		{"tenant audit events without a principal", http.MethodGet, "/api/v1/audit/events", nil, ""},
	}
	for _, c := range corpus {
		a := rawRequest(t, base.Addr(), c.method, c.path, c.headers, c.body)
		b := rawRequest(t, cand.Addr(), c.method, c.path, c.headers, c.body)
		if a.status != b.status {
			t.Errorf("%s: status line differs", c.name)
			continue
		}
		if strings.Contains(a.status, " 404 ") || strings.Contains(a.status, " 5") {
			t.Errorf("%s: answered %q; the corpus must reach a mounted route that answers", c.name, a.status)
		}
		if len(a.headers) != len(b.headers) {
			t.Errorf("%s: %d headers against %d", c.name, len(a.headers), len(b.headers))
			continue
		}
		for i := range a.headers {
			an, av, _ := strings.Cut(a.headers[i], ":")
			bn, bv, _ := strings.Cut(b.headers[i], ":")
			if an != bn {
				t.Errorf("%s: header %d is %q against %q", c.name, i, an, bn)
				continue
			}
			if strings.EqualFold(an, "Date") {
				for _, v := range []string{av, bv} {
					if _, err := http.ParseTime(strings.TrimSpace(v)); err != nil {
						t.Errorf("%s: Date is not an HTTP date", c.name)
					}
				}
				continue
			}
			if av != bv {
				t.Errorf("%s: header %s differs", c.name, an)
			}
		}
		if !bytes.Equal(a.body, b.body) {
			t.Errorf("%s: body differs (%d bytes against %d)", c.name, len(a.body), len(b.body))
		}
	}
}

type rawResponse struct {
	status  string
	headers []string // "Name: value", in the order the server wrote them
	body    []byte
}

// rawRequest sends one HTTP/1.1 request on a fresh connection and reads the
// answer's bytes without a client that would reorder or fold its headers.
func rawRequest(t *testing.T, addr, method, path string, headers map[string]string, body string) rawResponse {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var req strings.Builder
	// A fixed X-Request-Id: the server takes the caller's id (mw.RequestIDMiddleware)
	// instead of minting a random one, so the echoed header is comparable too.
	req.WriteString(method + " " + path + " HTTP/1.1\r\nHost: idp.example.test\r\nConnection: close\r\n" +
		"X-Request-Id: seam1-" + itoa(len(path)+len(body)) + "\r\n")
	for _, k := range []string{"Authorization", "Content-Type"} {
		if v, ok := headers[k]; ok {
			req.WriteString(k + ": " + v + "\r\n")
		}
	}
	if method == http.MethodPost {
		req.WriteString("Content-Length: " + itoa(len(body)) + "\r\n")
	}
	req.WriteString("\r\n" + body)
	if _, err := io.WriteString(conn, req.String()); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read the status line: %v", err)
	}
	var out rawResponse
	out.status = strings.TrimRight(status, "\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read a header: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		out.headers = append(out.headers, line)
	}
	out.body, _ = io.ReadAll(r)
	return out
}

func pathOf(t *testing.T, endpoint string) string {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil || u.Path == "" {
		t.Fatalf("discovery endpoint is not a URL with a path")
	}
	return u.Path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
