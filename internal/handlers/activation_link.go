package handlers

import (
	"net/url"
	"strings"
)

// THE-UNUSABLE-TOKEN (2026-08-31): an activation token that no one can
// consume is not a credential, it is litter.
//
// The org-create and resend-activation responses returned a BARE token. The
// only code that ever turned a token into something a human could use lived
// in the SMTP notifier — so with email unconfigured (the ordinary state of a
// fresh install) the operator was handed a secret with no consumption path:
// the /activate page reads ?token from the query string and offers no input
// field. The owner hit exactly that.
//
// These helpers give both handlers ONE definition of the link, matching the
// notifier's construction byte for byte (base + "/activate?token=<raw>").
//
// WHY THE UI BASE URL AND NOTHING ELSE: /activate is a page served by the
// identuum-ui frontend, not a route on this IdP. Falling back to the issuer
// (this server's own origin) would compose a link that 404s — a guess
// wearing the costume of an answer. When the UI base URL is unset we return
// NO link and say so, naming the setting the operator must set. An honest
// refusal beats a broken link.
const activationLinkSettingName = "IDENTUUM_IDP_UI_PUBLIC_BASE_URL"

// activationLink returns the absolute activation URL for rawToken, or an
// empty string when no base URL is configured.
func activationLink(uiBaseURL, rawToken string) string {
	base := strings.TrimRight(strings.TrimSpace(uiBaseURL), "/")
	if base == "" || strings.TrimSpace(rawToken) == "" {
		return ""
	}
	params := url.Values{}
	params.Set("token", rawToken)
	return base + "/activate?" + params.Encode()
}

// activationLinkUnavailableReason is the operator-facing explanation used
// when no link can be built. It names the setting rather than describing a
// deployment topology: email being unconfigured says nothing about whether
// the install is networked, and claiming otherwise is the same lying-message
// class this slice exists to remove.
func activationLinkUnavailableReason() string {
	return "no activation link can be built because " + activationLinkSettingName +
		" is not set; set it to the browser-facing base URL of the identuum-ui " +
		"frontend (for example http://localhost:7104) and re-issue the token"
}

// applyActivationLinkFields writes the activation_url / activation_url_
// unavailable pair into a response body. EXACTLY ONE of the two is ever
// present, so a client can branch on presence without guessing:
//
//	activation_url             absolute link, ready to open
//	activation_url_unavailable why no link exists, naming the setting
func applyActivationLinkFields(body map[string]any, uiBaseURL, rawToken string) {
	if link := activationLink(uiBaseURL, rawToken); link != "" {
		body["activation_url"] = link
		return
	}
	body["activation_url_unavailable"] = activationLinkUnavailableReason()
}
