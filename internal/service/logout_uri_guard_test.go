package service

import (
	"errors"
	"testing"
)

// A per-client backchannel logout URI is accepted only when it is absolute
// (has a host) and carries no #fragment, and — when https is required — uses
// the https scheme, before the server ever POSTs a logout token to it. An
// empty URI is allowed (the field is optional). Asserts the guard's returned
// sentinel for the shapes a delivery must never reach.
// RULE: LOGOUT-URI-GUARD-1
func TestValidateLogoutURI_AbsoluteHTTPSNoFragment(t *testing.T) {
	// Empty is allowed (nullable field).
	if err := validateLogoutURI("", true); err != nil {
		t.Errorf("empty logout URI must be allowed, got %v", err)
	}

	// Missing host → refused (relative or scheme-only).
	for _, raw := range []string{"/logout", "https://"} {
		if err := validateLogoutURI(raw, true); !errors.Is(err, ErrBackchannelHTTPSRequired) {
			t.Errorf("logout URI %q without a host must be refused, got %v", raw, err)
		}
	}

	// Fragment → refused even when otherwise well-formed.
	if err := validateLogoutURI("https://rp.example.com/logout#frag", true); !errors.Is(err, ErrBackchannelURIHasFragment) {
		t.Errorf("logout URI with a fragment must be refused, got %v", err)
	}

	// Plain http under requireHTTPS → refused.
	if err := validateLogoutURI("http://rp.example.com/logout", true); !errors.Is(err, ErrBackchannelHTTPSRequired) {
		t.Errorf("plaintext-http logout URI must be refused when https is required, got %v", err)
	}

	// A well-formed https logout URI passes.
	if err := validateLogoutURI("https://rp.example.com/backchannel-logout", true); err != nil {
		t.Errorf("a well-formed https logout URI must be accepted, got %v", err)
	}
}
