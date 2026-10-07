package main

import (
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// OSS-DEVSEED-LIVE, measured by `make devseed-live`: a re-seed within one TOTP
// step of a site_admin sign-in failed with "mfa enroll complete → 401:
// {"error":"invalid_code"}". recover-site-admin gives the account a new
// secret, but the product refuses a step the USER already spent
// (TOTP-SINGLE-USE-1), so a code for that step is refused under the new secret
// too. enrolMFA retries once, with the next step's code, after that step
// begins.
func TestEnrolMFA_SpentStepRetriesOnceOnTheNextStep(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	clock := time.Date(2026, 10, 7, 12, 0, 10, 0, time.UTC) // 10s into a step
	spent := totp.Code(key, uint64(clock.Unix()/30), 6)
	next := totp.Code(key, uint64(clock.Unix()/30)+1, 6)

	var mu sync.Mutex
	var codes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		switch r.URL.Path {
		case "/api/v1/auth/login/mfa/enroll/initiate":
			_, _ = io.WriteString(w, `{"secret":"`+secret+`"}`)
		case "/api/v1/auth/login/mfa/enroll/complete":
			mu.Lock()
			codes = append(codes, body["code"])
			mu.Unlock()
			if body["code"] == spent {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"invalid_code"}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"bearer-1"}`)
		}
	}))
	defer srv.Close()

	oldNow, oldSleep := totpNow, totpSleep
	defer func() { totpNow, totpSleep = oldNow, oldSleep }()
	var slept time.Duration
	totpNow = func() time.Time { return clock }
	totpSleep = func(d time.Duration) { slept += d; clock = clock.Add(d) }

	bearer, gotSecret, err := enrolMFA(srv.URL, "00000000-0000-7000-0000-000000000001")
	if err != nil || bearer != "bearer-1" || gotSecret != secret {
		t.Fatalf("enrolMFA = %q, %v; want the bearer after one retry", bearer, err)
	}
	if len(codes) != 2 || codes[0] != spent || codes[1] != next {
		t.Fatalf("complete was sent %d code(s); want the spent step's code, then the next step's", len(codes))
	}
	if slept < 20*time.Second || slept > 21*time.Second {
		t.Errorf("waited %s; want until the next step begins (20s here, plus at most 1s)", slept)
	}
}

// A refusal other than invalid_code is never retried.
func TestEnrolMFA_OtherRefusalIsNotRetried(t *testing.T) {
	completes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login/mfa/enroll/initiate":
			_, _ = io.WriteString(w, `{"secret":"JBSWY3DPEHPK3PXP"}`)
		case "/api/v1/auth/login/mfa/enroll/complete":
			completes++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"session_expired"}`)
		}
	}))
	defer srv.Close()
	oldNow, oldSleep := totpNow, totpSleep
	defer func() { totpNow, totpSleep = oldNow, oldSleep }()
	totpNow = func() time.Time { return time.Date(2026, 10, 7, 12, 0, 10, 0, time.UTC) }
	totpSleep = func(time.Duration) { t.Error("slept for a refusal that is not invalid_code") }

	if _, _, err := enrolMFA(srv.URL, "00000000-0000-7000-0000-000000000001"); err == nil || completes != 1 {
		t.Fatalf("err %v after %d complete(s); want one refused attempt", err, completes)
	}
}
