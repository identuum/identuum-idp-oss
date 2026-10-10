package main

import (
	"fmt"
	"strings"

	"github.com/identuum/identuum-idp-oss/tools/testdburl"
)

// selectTarget returns the explicit test URL once it passes the accepted-URL
// policy (tools/testdburl, the same one the Makefile's test-db-endpoint guard
// applies; endpoint_test.go runs one case table through both). It has no
// default and no fallback: a missing IDENTUUM_IDP_TEST_DATABASE_URL is a
// refusal, never the 5513 default or the development IDENTUUM_IDP_DATABASE_URL.
func selectTarget(getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv("IDENTUUM_IDP_TEST_DATABASE_URL"))
	if raw == "" {
		return "", fmt.Errorf("IDENTUUM_IDP_TEST_DATABASE_URL is not set; the witness has no default database and does not fall back to IDENTUUM_IDP_DATABASE_URL (run it through make verify-integration with DEV_PG_HOST_PORT set to a scratch server)")
	}
	if err := testdburl.CheckEnv(raw, getenv); err != nil {
		return "", err
	}
	return raw, nil
}
