package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ownerPort is the owner's own PostgreSQL (agent-rules.md §H-bis). No local
// test run uses it; the hosted CI runner's own service database is the one
// exception (judge ruling Q1(a), OSS-MINT-GUARD-2).
const ownerPort = "5513"

// hostedRunnerDatabase is the only database the hosted exception admits on
// ownerPort: the one the Integration Tests job's service container creates.
const hostedRunnerDatabase = "identuum_idp_oss_test"

// checkTestURL is the accepted-URL policy for an integration test database,
// the same one the Makefile's test-db-endpoint guard applies (endpoint_test.go
// runs one case table through both). It judges the EFFECTIVE endpoint by
// refusing everything pgx could read as another one: the URL must be
// postgres:// or postgresql://, with optional userinfo, ONE literal host
// 127.0.0.1 or localhost on the selected port, a path naming a database of
// letters, digits and underscores that ends in _test, and no option but a
// single sslmode. A host, hostaddr, port, dbname, database, service or
// servicefile option (percent-encoded or not), a host list, a socket
// directory, a fragment or a percent escape outside the userinfo is refused,
// never resolved. It reads no environment, file or network. Messages name the
// rule, never the URL.
func checkTestURL(raw, port string, hosted bool) error {
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("DEV_PG_HOST_PORT is not a port number")
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
	if port == ownerPort && (!hosted || db != hostedRunnerDatabase) {
		return fmt.Errorf("port %s is the owner's PostgreSQL; a local test run never uses it (only the hosted CI runner's own %s, with CI=true and GITHUB_ACTIONS=true). Set DEV_PG_HOST_PORT to a scratch server's port", ownerPort, hostedRunnerDatabase)
	}
	return nil
}

// selectTarget returns the explicit test URL once it passes checkTestURL. It
// has no default and no fallback: a missing IDENTUUM_IDP_TEST_DATABASE_URL is
// a refusal, never the 5513 default or the development IDENTUUM_IDP_DATABASE_URL.
func selectTarget(getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv("IDENTUUM_IDP_TEST_DATABASE_URL"))
	if raw == "" {
		return "", fmt.Errorf("IDENTUUM_IDP_TEST_DATABASE_URL is not set; the witness has no default database and does not fall back to IDENTUUM_IDP_DATABASE_URL (run it through make verify-integration with DEV_PG_HOST_PORT set to a scratch server)")
	}
	hosted := getenv("CI") == "true" && getenv("GITHUB_ACTIONS") == "true"
	if err := checkTestURL(raw, strings.TrimSpace(getenv("DEV_PG_HOST_PORT")), hosted); err != nil {
		return "", err
	}
	return raw, nil
}
