package runtime

import (
	"os"
	"strconv"
	"strings"
)

// public_hardening_config.go — operator hardening toggles for the PUBLIC
// (unauthenticated) surface. Same getenv-hook convention as
// ratelimit_config.go / smtp_config.go so the resolution is unit-testable
// without a live process (tests inject a stub getenv).

// resolveHidePublicIDPEmailDomains reports whether the operator asked to OMIT
// email_domains from the PUBLIC organization-lookup projection, via
//
//	IDENTUUM_IDP_PUBLIC_HIDE_IDP_EMAIL_DOMAINS
//
// The value is parsed with strconv.ParseBool (accepts 1/t/T/TRUE/true/... and
// 0/f/F/FALSE/false/...). Unset, empty, or MALFORMED ⇒ false: the safe default
// is the current behavior (email_domains exposed), so a bad value never hides
// the field unexpectedly and never faults the process (P-018). This gates ONLY
// the public lookup — the authenticated org-admin identity-provider API returns
// email_domains regardless.
func resolveHidePublicIDPEmailDomains(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	v, err := strconv.ParseBool(strings.TrimSpace(getenv("IDENTUUM_IDP_PUBLIC_HIDE_IDP_EMAIL_DOMAINS")))
	if err != nil {
		return false // unset / empty / malformed → exposed (safe default)
	}
	return v
}
