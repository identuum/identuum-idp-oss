package handlers

import (
	"net/url"
	"strings"
	"testing"
)

// THE-UNUSABLE-TOKEN: a returned activation token must arrive with the link
// that consumes it, or with an honest refusal naming the setting — never a
// guessed URL, and never a bare token with no consumption path.
//
// RULE: ACTIVATION-LINK-USABLE-1
func TestActivationLinkFields_LinkOrHonestRefusal_NeverAGuess(t *testing.T) {
	const raw = "raw-activation-token-value"

	t.Run("configured UI base URL yields the consumable link, and no refusal", func(t *testing.T) {
		body := map[string]any{"activation_token": raw}
		applyActivationLinkFields(body, "http://localhost:7104", raw)

		link, ok := body["activation_url"].(string)
		if !ok || link == "" {
			t.Fatalf("activation_url missing; body = %v", body)
		}
		if _, present := body["activation_url_unavailable"]; present {
			t.Fatalf("both fields present — exactly one must be: %v", body)
		}

		// The link must be the one the /activate page can actually consume:
		// the token travels in the ?token query parameter it reads.
		u, err := url.Parse(link)
		if err != nil {
			t.Fatalf("activation_url is not a URL: %v", err)
		}
		if u.Path != "/activate" {
			t.Fatalf("activation_url path = %q, want /activate", u.Path)
		}
		if got := u.Query().Get("token"); got != raw {
			t.Fatalf("activation_url token = %q, want the raw token", got)
		}
		if u.Host != "localhost:7104" {
			t.Fatalf("activation_url host = %q, want the configured UI origin", u.Host)
		}
	})

	t.Run("unset UI base URL yields NO link and a reason naming the setting", func(t *testing.T) {
		for _, base := range []string{"", "   "} {
			body := map[string]any{"activation_token": raw}
			applyActivationLinkFields(body, base, raw)

			if _, present := body["activation_url"]; present {
				t.Fatalf("a link was guessed with base %q: %v", base, body)
			}
			reason, ok := body["activation_url_unavailable"].(string)
			if !ok || reason == "" {
				t.Fatalf("no honest refusal with base %q: %v", base, body)
			}
			// The refusal must name the setting the operator has to set,
			// so the message is actionable rather than merely apologetic.
			if !strings.Contains(reason, "IDENTUUM_IDP_UI_PUBLIC_BASE_URL") {
				t.Fatalf("refusal does not name the setting: %q", reason)
			}
			// And it must NOT assert a deployment topology it never
			// established — the lying-message class this slice removes.
			lowered := strings.ToLower(reason)
			for _, banned := range []string{"air-gap", "air gap", "airgap"} {
				if strings.Contains(lowered, banned) {
					t.Fatalf("refusal asserts an unestablished topology (%q): %q", banned, reason)
				}
			}
		}
	})

	t.Run("the token is never smuggled into the response as a link when absent", func(t *testing.T) {
		body := map[string]any{}
		applyActivationLinkFields(body, "http://localhost:7104", "")
		if _, present := body["activation_url"]; present {
			t.Fatalf("a link was built without a token: %v", body)
		}
		if _, present := body["activation_url_unavailable"]; !present {
			t.Fatalf("no reason emitted for the empty-token case: %v", body)
		}
	})
}
