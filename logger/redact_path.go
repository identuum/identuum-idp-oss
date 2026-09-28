package logger

import (
	"path"
	"strings"
)

// credentialPathPrefixes are the routes whose last path segment is a
// one-time credential (the api-docgen manifest's two `:token` routes).
var credentialPathPrefixes = []string{
	"/api/v1/auth/invite/",
	"/api/v1/auth/organizations/activate/",
}

// RedactPath returns the request path fit for a log line or audit row: on a
// route whose path carries a one-time token, the route template
// (".../:token") instead of the token; every other path unchanged.
// OSS-ONBOARD-B: the invite and activation links' tokens reached the access
// log, the rate-limit and auth-refusal lines and the denial audit rows.
func RedactPath(p string) string {
	clean := path.Clean(p)
	for _, prefix := range credentialPathPrefixes {
		if rest, ok := strings.CutPrefix(clean, prefix); ok && rest != "" {
			return prefix + ":token"
		}
	}
	return p
}
