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
	"runtime"
	"strconv"
	"strings"
)

// OwnerPort is the owner's own PostgreSQL (agent-rules.md §H-bis). No local
// test run uses it; the hosted CI runner's own service database is the one
// exception (judge ruling Q1(a), OSS-MINT-GUARD-2).
const OwnerPort = "5513"

// HostedDatabase is the only database the hosted exception admits on
// OwnerPort: the one the Integration Tests job's service container creates.
const HostedDatabase = "identuum_idp_oss_test"

// HostedJob is the job id of .github/workflows/ci.yml's Integration Tests job,
// the one job whose service container is published on OwnerPort.
const HostedJob = "integration"

// Hosted reports whether this process declares itself the hosted Integration
// Tests job: a Linux host, CI=true, GITHUB_ACTIONS=true, GITHUB_JOB=integration
// and RUNNER_OS=Linux, as GitHub Actions sets them for that job.
//
// WHAT THIS BINDING PROVES, and what it does not. On any host that is not
// Linux — the owner's macOS workstation, where 5513 is the protected server —
// the exception cannot apply, whatever the environment says: the operating
// system is the compiled runtime's, not a variable. On Linux it rests on four
// declarations that GitHub Actions sets for that job and that an ordinary
// local shell does not; a caller who deliberately sets all four on a Linux
// host is believed. It does not prove that the server answering on 5513 is the
// job's service container.
func Hosted(getenv func(string) string) bool {
	return hosted(getenv, runtime.GOOS)
}

func hosted(getenv func(string) string, goos string) bool {
	return goos == "linux" &&
		getenv("CI") == "true" &&
		getenv("GITHUB_ACTIONS") == "true" &&
		getenv("GITHUB_JOB") == HostedJob &&
		getenv("RUNNER_OS") == "Linux"
}

// CheckEnv judges raw against the selected port DEV_PG_HOST_PORT and the
// hosted declaration, both read through getenv.
func CheckEnv(raw string, getenv func(string) string) error {
	return Check(raw, strings.TrimSpace(getenv("DEV_PG_HOST_PORT")), Hosted(getenv))
}

// Check is the accepted-URL policy. It judges the EFFECTIVE endpoint by
// refusing everything pgx could read as another one: the URL must be
// postgres:// or postgresql://, with optional userinfo, ONE literal host
// 127.0.0.1 or localhost on the selected port, a path naming a database of
// letters, digits and underscores that ends in _test, and no option but a
// single sslmode. A host, hostaddr, port, dbname, database, service or
// servicefile option (percent-encoded or not), a host list, a socket
// directory, a fragment or a percent escape outside the userinfo is refused,
// never resolved. On OwnerPort only HostedDatabase is accepted, and only when
// hosted. It reads no environment, file or network. Messages name the rule,
// never the URL.
func Check(raw, port string, hosted bool) error {
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
	if port == OwnerPort && (!hosted || db != HostedDatabase) {
		return fmt.Errorf("port %s is the owner's PostgreSQL; a local test run never uses it (only the hosted Integration Tests job's own %s, on a Linux runner with CI=true, GITHUB_ACTIONS=true, GITHUB_JOB=%s and RUNNER_OS=Linux). Set DEV_PG_HOST_PORT to a scratch server's port", OwnerPort, HostedDatabase, HostedJob)
	}
	return nil
}
