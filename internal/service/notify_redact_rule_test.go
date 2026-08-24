package service

import "testing"

// maskEmail redacts the local-part of an email before it reaches a log/notifier:
// it emits at most the first character of the local part followed by stars, and
// falls back to "***" when there is no usable local part. The full local part
// (and thus the recipient identity beyond its first character) never survives.
// RULE: NOTIFY-REDACT-1
func TestMaskEmail_NeverLeaksLocalPart(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice@example.com", "a****@example.com"},
		{"a@b.com", "*@b.com"},
		{"noatsign", "***"},
		{"@x.com", "***"},
	}
	for _, c := range cases {
		if got := maskEmail(c.in); got != c.want {
			t.Errorf("maskEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
