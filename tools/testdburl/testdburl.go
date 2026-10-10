// Package testdburl is the one Go form of the accepted-URL policy for a test
// database: tools/integration-witness judges its explicit URL with it, and
// internal/testsupport.RequireTestDatabase judges every DB-backed suite's URL
// with it (review OSS-MINT-GUARD-2 G1). The Makefile's test-db-endpoint guard
// is the shell form of the same policy; tools/integration-witness/endpoint_test.go
// runs one case table through both. It is imported by a maintainer tool and by
// test support only, so it never links into the product binary.
package testdburl

import (
	"fmt"
	"strconv"
	"strings"
)

// OwnerPort is the owner's own PostgreSQL (agent-rules.md §H-bis). No test run
// uses it, on any host and in any job: the CI workflow's test databases are
// published on CIPort instead (judge ruling Q-HOSTED (a), OSS-MINT-GUARD-4), so
// no environment, CI's included, admits OwnerPort.
const OwnerPort = "5513"

// CIPort is the host port .github/workflows/ci.yml publishes its test
// PostgreSQL services on and sets as DEV_PG_HOST_PORT: neither OwnerPort nor
// PostgreSQL's own 5432. It is an ordinary scratch port to this policy.
const CIPort = "45432"

// CheckEnv judges raw against the selected port DEV_PG_HOST_PORT, read
// through getenv. No other variable is read.
func CheckEnv(raw string, getenv func(string) string) error {
	return Check(raw, strings.TrimSpace(getenv("DEV_PG_HOST_PORT")))
}

// Check is the accepted-URL policy. OwnerPort is refused first, whatever the
// URL. Otherwise it judges the EFFECTIVE endpoint by refusing everything pgx
// could read as another one: the URL must be postgres:// or postgresql://,
// with optional userinfo, ONE literal host 127.0.0.1 or localhost on the
// selected port, a path naming a database of letters, digits and underscores
// that ends in _test, and no option but a single sslmode. A host, hostaddr,
// port, dbname, database, service or servicefile option (percent-encoded or
// not), a host list, a socket directory, a fragment or a percent escape
// outside the userinfo is refused, never resolved. It reads no environment,
// file or network. Messages name the rule, never the URL.
func Check(raw, port string) error {
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("DEV_PG_HOST_PORT is not a port number")
	}
	if port == OwnerPort {
		return fmt.Errorf("port %s is the owner's PostgreSQL; no test run uses it, in CI or anywhere else. Set DEV_PG_HOST_PORT to a scratch server's port", OwnerPort)
	}
	var rest string
	switch {
	case strings.HasPrefix(raw, "postgres://"):
		rest = strings.TrimPrefix(raw, "postgres://")
	case strings.HasPrefix(raw, "postgresql://"):
		rest = strings.TrimPrefix(raw, "postgresql://")
	default:
		return fmt.Errorf("the test URL is not a postgres:// URL, so its server cannot be checked")
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 || rest[end] != '/' {
		return fmt.Errorf("the test URL has no /database path after its server")
	}
	authority, path := rest[:end], rest[end+1:]
	hostPort := authority[strings.LastIndex(authority, "@")+1:]
	if hostPort != "127.0.0.1:"+port && hostPort != "localhost:"+port {
		return fmt.Errorf("the test URL does not name 127.0.0.1:%s or localhost:%s, the selected scratch server", port, port)
	}
	db, query, _ := strings.Cut(path, "?")
	if db == "" || strings.Trim(db, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
		return fmt.Errorf("the test URL's database name is not plain letters, digits and underscores")
	}
	if !strings.HasSuffix(db, "_test") {
		return fmt.Errorf("the test URL's database %s does not end in _test", db)
	}
	if query != "" {
		mode, ok := strings.CutPrefix(query, "sslmode=")
		if !ok || mode == "" || strings.Trim(mode, "abcdefghijklmnopqrstuvwxyz-") != "" {
			return fmt.Errorf("the test URL carries a connection option other than one sslmode; host, hostaddr, port, dbname, database and service options can send the driver to another server or database, so none is accepted")
		}
	}
	return nil
}
