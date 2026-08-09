package types

// ============================================================================
// OAuth Protocol Response Types
// These DTOs are returned directly by OIDC/OAuth handlers. They are distinct
// from the internal TokenResponse and are shaped to match the wire formats
// required by RFC 6749, RFC 8693, and RFC 9126 respectively.
// ============================================================================

// OAuth2TokenResponse represents the standard OAuth2/OIDC token response
type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuth2TokenExchangeResponse represents the RFC 8693 §2.2 token exchange response.
// It differs from OAuth2TokenResponse by including issued_token_type, which identifies
// the type of token that was issued. When offline_access is requested and a gateway
// session is successfully persisted, refresh_token is also included so the caller can
// use the refresh_token grant to silently renew its short-lived LLM access token.
type OAuth2TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	ExpiresIn       int    `json:"expires_in"`
}

// PARResponse represents the Pushed Authorization Request response
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}
