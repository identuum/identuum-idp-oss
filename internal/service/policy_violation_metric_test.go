package service

// Regression guard for the AuthPolicyViolation label-cardinality fix
// (docs/audit/changelog/authpolicyviolation-label-cardinality-fix.md):
// the token-reuse emissions must NEVER carry a user UUID / subject (or
// any unbounded, attacker-drivable value) as a metric label — one series
// per replayed victim would be a cardinality DoS on a security metric
// now that /metrics is a real exporter. Both breach paths must still be
// DETECTED and COUNTED (auth logic unchanged); only the label is bounded.
//
// Assertions run against a live scrape of the default registry (the
// same registry the internal /metrics listener serves), so they hold
// for exactly what an operator's Prometheus would ingest.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// boundedTokenReuseSeries is the exposition series the fixed emissions
// write to (labels are alphabetical in exposition order).
const boundedTokenReuseSeries = `identuum_idp_policy_violation_total{org_id="",policy="token_reuse"}`

// scrapePolicyViolation returns the family's exposition lines plus the
// current value of the bounded token-reuse series (0 when absent).
func scrapePolicyViolation(t *testing.T) (lines []string, boundedValue float64) {
	t.Helper()
	h := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, "identuum_idp_policy_violation_total") {
			continue
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, boundedTokenReuseSeries) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, boundedTokenReuseSeries)), 64); err == nil {
				boundedValue = v
			}
		}
	}
	return lines, boundedValue
}

// (c)+(e) Session-rotation reuse: the breach is still detected
// (ErrUserSessionReuse) and still counted, but under the bounded
// {policy="token_reuse", org_id=""} series — the victim's user UUID
// must appear in NO policy-violation label.
func TestTokenReuseMetric_SessionRotation_NoUserUUIDLabel(t *testing.T) {
	_, before := scrapePolicyViolation(t)

	repo := newSessionRepo()
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	uid := uuid.New()
	first, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.RotateRefreshToken(context.Background(), first.RefreshToken); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Replay the rotated-away token → reuse. (e): detection unchanged.
	_, reuseErr := svc.RotateRefreshToken(context.Background(), first.RefreshToken)
	if !errors.Is(reuseErr, ErrUserSessionReuse) {
		t.Fatalf("err = %v, want ErrUserSessionReuse (detection must be unchanged)", reuseErr)
	}

	lines, after := scrapePolicyViolation(t)
	// (e) still recorded: the bounded series incremented.
	if after < before+1 {
		t.Errorf("token_reuse{org_id=\"\"} = %v, want >= %v (+1) — the violation must still be counted", after, before+1)
	}
	// (c) HARD RULE: the user UUID appears in NO policy-violation label.
	for _, line := range lines {
		if strings.Contains(line, uid.String()) {
			t.Fatalf("user UUID leaked into a policy-violation metric label (cardinality bomb): %s", line)
		}
	}
}

// (c)+(e) OAuth refresh-token reuse (Consume path): same guarantees for
// the second emit site — subject never a label, violation still counted.
func TestTokenReuseMetric_OAuthRefreshConsume_NoSubjectLabel(t *testing.T) {
	_, before := scrapePolicyViolation(t)

	repo := newInMemoryRefreshTokenRepo()
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	subject := uuid.New().String()
	issued, err := svc.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-1", Subject: subject})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli-1"}); err != nil {
		t.Fatalf("first consume (rotation): %v", err)
	}
	// Replay the rotated-away token → reuse. (e): detection unchanged.
	_, reuseErr := svc.Consume(context.Background(), ConsumeRefreshTokenInput{RawToken: issued.Token, ClientID: "cli-1"})
	if !errors.Is(reuseErr, domain.ErrRefreshTokenReuse) {
		t.Fatalf("err = %v, want domain.ErrRefreshTokenReuse (detection must be unchanged)", reuseErr)
	}

	lines, after := scrapePolicyViolation(t)
	if after < before+1 {
		t.Errorf("token_reuse{org_id=\"\"} = %v, want >= %v (+1) — the violation must still be counted", after, before+1)
	}
	for _, line := range lines {
		if strings.Contains(line, subject) {
			t.Fatalf("subject leaked into a policy-violation metric label (cardinality bomb): %s", line)
		}
	}
}
