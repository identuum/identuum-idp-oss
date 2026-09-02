package types

// OIDCProviderMetadata represents the OpenID Connect discovery document
// Ref: https://openid.net/specs/openid-connect-discovery-1_0.html
type OIDCProviderMetadata struct {
	Issuer                             string   `json:"issuer"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint,omitempty"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	UserinfoEndpoint                   string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint                 string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint              string   `json:"introspection_endpoint,omitempty"`
	JwksURI                            string   `json:"jwks_uri"`
	ResponseTypesSupported             []string `json:"response_types_supported"`
	ResponseModesSupported             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported              []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported   []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported      []string `json:"code_challenge_methods_supported"`
	ScopesSupported                    []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported  []string `json:"token_endpoint_auth_methods_supported"`
	// TokenEndpointAuthSigningAlgValuesSupported — OIDC Discovery 1.0 §3.
	// Lists the JWS alg values accepted for private_key_jwt assertions.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	// RevocationEndpointAuthMethodsSupported — RFC 7009 §4. Populated in
	// discovery once /auth/revoke enforces client authentication (§2.10).
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                        []string `json:"claims_supported"`
	AcrValuesSupported                     []string `json:"acr_values_supported,omitempty"`
	// RegistrationEndpoint — RFC 7591 dynamic client registration endpoint.
	// Only advertised when the DynamicClientRegistration feature is enabled.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
}

// OIDCUserInfo represents the response from the UserInfo endpoint
// Ref: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
type OIDCUserInfo struct {
	Sub  string `json:"sub"`
	Name string `json:"name,omitempty"`
	// OIDC Core §5.1 profile claims (THE-PROFILE-CLAIMS). Each is emitted
	// only when the user set it — never a placeholder. UpdatedAt is Unix
	// seconds of the last profile/user update.
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	Email             string `json:"email,omitempty"`
	OrganizationID    string `json:"organization_id,omitempty"`
	Role              string `json:"role,omitempty"`
	// EmailVerified accompanies `email` (OIDC Core §5.1: both belong to the
	// `email` scope) and is omitted whenever email is — §5.3.2 forbids a
	// claim rendered without a value.
	EmailVerified *bool `json:"email_verified,omitempty"`
}
