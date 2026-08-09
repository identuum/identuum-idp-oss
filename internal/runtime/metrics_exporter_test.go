package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// smtpMetricsTestUser builds the minimal user the notifier needs.
func smtpMetricsTestUser() *domain.User {
	return &domain.User{ID: uuid.New(), Email: "metrics@example.com"}
}

// scrapeMetrics starts ONLY the internal metrics listener (no DB, no
// public engine) and returns one live scrape of /metrics through the
// real promhttp handler.
func scrapeMetrics(t *testing.T) string {
	t.Helper()
	r := &Runtime{cfg: Config{
		MetricsAddr: "127.0.0.1:0",
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}}
	r.startMetricsListener()
	if r.metricsListener == nil {
		t.Fatal("metrics listener failed to bind")
	}
	t.Cleanup(func() {
		if r.metricsSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = r.metricsSrv.Shutdown(ctx)
		}
	})

	resp, err := http.Get("http://" + r.metricsListener.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// (c) LIVE SCRAPE: after triggering a REAL 429 (through the actual
// rate-limit middleware) and a REAL SMTP delivery attempt (through the
// actual notifier's error path), the internal metrics listener serves
// genuine Prometheus exposition carrying identuum_idp_ratelimit_hits_total
// and identuum_idp_email_delivery_total — not the retired placeholder.
func TestMetricsListener_LiveScrape_RealCollectors(t *testing.T) {
	// Trigger a real 429 → RateLimitHits{route}.Inc() (rate_limit.go).
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(mw.NewRateLimitMiddleware(ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: time.Minute}, "metrics-test"))
	engine.GET("/limited", func(c *gin.Context) { c.Status(http.StatusOK) })
	for i := 0; i < 2; i++ { // 2nd request → 429 → metric increment
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "203.0.113.20:4444"
		engine.ServeHTTP(rec, req)
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("2nd request: status = %d, want 429 (needed to increment RateLimitHits)", rec.Code)
		}
	}

	// Trigger a real SMTP delivery attempt → EmailDelivery{kind,result}.Inc()
	// via the notifier's genuine error path (dead endpoint → relay_error).
	n := service.NewSMTPNotifier(service.SMTPNotifierConfig{Host: "127.0.0.1", Port: 1, From: "no-reply@idp.test"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	u := smtpMetricsTestUser()
	if err := n.SendPasswordResetEmail(ctx, u, "https://ui/reset?token=x"); err == nil {
		t.Fatal("expected delivery error against a dead endpoint (needed to increment EmailDelivery)")
	}

	body := scrapeMetrics(t)

	// Real exposition, not the placeholder.
	if !strings.Contains(body, "# HELP") || !strings.Contains(body, "go_goroutines") {
		t.Errorf("scrape does not look like real Prometheus exposition; head:\n%.400s", body)
	}
	if strings.Contains(body, "Prometheus exporter not yet wired") {
		t.Error("placeholder string still served — exporter not wired")
	}
	// The two audit-flagged collectors are present WITH live series.
	if !strings.Contains(body, `identuum_idp_ratelimit_hits_total{route="/limited"}`) {
		t.Errorf("scrape missing live RateLimitHits series; got:\n%s", grepLines(body, "ratelimit"))
	}
	if !strings.Contains(body, `identuum_idp_email_delivery_total{kind="password_reset",result="relay_error"}`) {
		t.Errorf("scrape missing live EmailDelivery series; got:\n%s", grepLines(body, "email_delivery"))
	}
}

// (e) Building the exporter handler repeatedly (re-listen after a
// bind retry, tests, etc.) cannot panic: collectors are registered
// once at package init via promauto; the handler itself performs no
// registration.
func TestMetricsExporterHandler_RepeatedBuildNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("building/serving the exporter handler panicked: %v", r)
		}
	}()
	for i := 0; i < 3; i++ {
		h := metricsExporterHandler()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("build %d: status = %d, want 200", i+1, rec.Code)
		}
	}
}

// grepLines returns the scrape lines containing substr (test-failure aid).
func grepLines(body, substr string) string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return "(no matching lines)"
	}
	return strings.Join(out, "\n")
}
