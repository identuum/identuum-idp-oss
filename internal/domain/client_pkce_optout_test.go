package domain

import (
	"errors"
	"testing"
)

// OSS-PUBLIC-CLIENT-PKCE-OPTION: "PKCE required" may be turned off only for a
// public client an org_admin created. The zero value keeps it required.
func TestClient_PKCEOptOutIsForAConsoleCreatedPublicClientOnly(t *testing.T) {
	base := func() *Client {
		return &Client{ClientID: "c", Name: "app", RedirectURIs: []string{"https://app.example.com/cb"}}
	}
	public := base()
	public.IsPublic, public.TokenEndpointAuthMethod = true, "none"
	if !public.RequiresPKCE() {
		t.Error("a public client with the zero value must require PKCE")
	}
	public.PKCEOptOut = true
	if err := public.Validate(); err != nil || public.RequiresPKCE() {
		t.Errorf("opted-out public client: Validate = %v, RequiresPKCE = %v; want valid and not required", err, public.RequiresPKCE())
	}

	confidential := base()
	if confidential.RequiresPKCE() {
		t.Error("a confidential client never requires PKCE")
	}
	confidential.PKCEOptOut = true
	if err := confidential.Validate(); !errors.Is(err, ErrPKCEOptOutConfidentialClient) {
		t.Errorf("confidential opt-out: Validate = %v, want ErrPKCEOptOutConfidentialClient", err)
	}

	dynamic := base()
	dynamic.IsPublic, dynamic.TokenEndpointAuthMethod, dynamic.DynamicallyRegistered, dynamic.PKCEOptOut = true, "none", true, true
	if err := dynamic.Validate(); !errors.Is(err, ErrPKCEOptOutDynamicClient) {
		t.Errorf("dynamic opt-out: Validate = %v, want ErrPKCEOptOutDynamicClient", err)
	}
}
