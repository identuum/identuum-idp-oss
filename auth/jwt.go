package auth

// ============================================================================
// JWT Error Messages
// ============================================================================

const (
	// #nosec G101 - False positive: These are error message constants, not credentials
	ErrMsgInvalidTokenFormat = "Invalid token format"
	ErrMsgTokenExpired       = "Token expired"
	ErrMsgInvalidToken       = "Invalid token"
	ErrMsgNoToken            = "No token provided"
)

// NOTE: this package previously registered inert viper defaults here
// (JWT_ACCESS_TOKEN_EXPIRY / JWT_REFRESH_TOKEN_EXPIRY). Nothing ever read
// them via viper — the effective TTLs are the service-layer defaults on
// UserTokenServiceOptions / session TTLs — so they were removed along with
// the last direct viper dependency (integrity-audit residual NEW-1).
