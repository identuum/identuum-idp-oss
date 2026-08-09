// Package service — BackchannelLogoutService delivers an OIDC
// Back-Channel Logout 1.0 `logout_token` to a registered RP's
// `backchannel_logout_uri`. The service composes:
//
//   - `LogoutTokenService` to mint the JWT.
//   - `safehttp.NewSafeClient` (or an operator-supplied HTTPClient)
//     to POST the form-encoded payload over HTTPS.
//
// What this service WILL NOT do:
//
//   - Retry on transient failure. A future slice can add bounded
//     retry with exponential backoff; this slice keeps delivery
//     deterministic.
//   - Persist a delivery log. Audit emission via the supplied
//     audit.Service seam carries `{client_id, status}` only —
//     never the logout_token bytes.
package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// BackchannelLogoutService is the delivery façade.
type BackchannelLogoutService struct {
	tokens              *LogoutTokenService
	httpClient          *http.Client
	timeout             time.Duration
	allowPlainHTTP      bool
	deliveries          repository.BackchannelLogoutDeliveryRepository
	dueProcessorClients BackchannelDueProcessorClientLookup
	maxAttempts         int
	retryBackoff        time.Duration
	now                 func() time.Time
}

// BackchannelLogoutServiceOptions parameterises the service.
//
//   - HTTPClient overrides the default safehttp client. When nil,
//     `safehttp.NewSafeClient()` is used.
//   - Timeout caps the total POST round-trip; defaults to 3
//     seconds.
type BackchannelLogoutServiceOptions struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	// AllowPlainHTTP disables the HTTPS requirement on
	// `backchannel_logout_uri`. Intended ONLY for the test suite
	// (httptest.NewServer serves HTTP). Production must leave
	// this false.
	AllowPlainHTTP bool
}

// NewBackchannelLogoutService constructs the service. tokens
// required.
func NewBackchannelLogoutService(report *lifecycle.StartupReport, tokens *LogoutTokenService, opts BackchannelLogoutServiceOptions) *BackchannelLogoutService {
	if tokens == nil {
		report.Fatal("NewBackchannelLogoutService", "service: NewBackchannelLogoutService requires a non-nil LogoutTokenService")
	}
	client := opts.HTTPClient
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if client == nil {
		client = safehttp.NewSafeClient()
		client.Timeout = timeout
	}
	return &BackchannelLogoutService{
		tokens:         tokens,
		httpClient:     client,
		timeout:        timeout,
		allowPlainHTTP: opts.AllowPlainHTTP,
		maxAttempts:    3,
		retryBackoff:   30 * time.Second,
		now:            time.Now,
	}
}

// WithDeliveryRepository composes durable delivery row recording.
// When wired, Deliver records a pending row before the POST and
// flips it to delivered/failed afterwards. Without it wired, the
// service operates in fire-and-forget mode (the prior behavior).
func (s *BackchannelLogoutService) WithDeliveryRepository(r repository.BackchannelLogoutDeliveryRepository) *BackchannelLogoutService {
	s.deliveries = r
	return s
}

// WithRetryPolicy overrides the default maxAttempts (3) and
// retryBackoff (30s). maxAttempts < 1 → 1 (no retry).
func (s *BackchannelLogoutService) WithRetryPolicy(maxAttempts int, backoff time.Duration) *BackchannelLogoutService {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	s.maxAttempts = maxAttempts
	if backoff > 0 {
		s.retryBackoff = backoff
	}
	return s
}

// DeliverInput carries the per-delivery context.
type DeliverInput struct {
	Client    *domain.Client
	Subject   uuid.UUID
	SessionID uuid.UUID
}

// DeliverResult is the per-attempt projection. Status is the
// upstream HTTP status code (0 if no round-trip completed).
type DeliverResult struct {
	Delivered bool
	Status    int
	URL       string
}

// Sentinel errors.
var (
	ErrBackchannelNoURI          = errors.New("service: backchannel client has no logout_uri")
	ErrBackchannelHTTPSRequired  = errors.New("service: backchannel_logout_uri requires https")
	ErrBackchannelURIHasFragment = errors.New("service: backchannel_logout_uri must not contain a fragment")
	ErrBackchannelDeliveryFailed = errors.New("service: backchannel logout delivery failed")
)

// Deliver mints a logout_token and POSTs it to the client's
// registered backchannel_logout_uri.
//
// When the client carries no backchannel_logout_uri, returns
// `(nil, ErrBackchannelNoURI)` — the caller treats it as a no-op.
//
// When delivery fails (network error, non-2xx, etc.), returns
// `(*DeliverResult, ErrBackchannelDeliveryFailed)` so the caller
// can still surface the URL + status for the audit row.
func (s *BackchannelLogoutService) Deliver(ctx context.Context, in DeliverInput) (*DeliverResult, error) {
	if in.Client == nil {
		return nil, ErrBackchannelNoURI
	}
	if strings.TrimSpace(in.Client.BackchannelLogoutURI) == "" {
		return nil, ErrBackchannelNoURI
	}
	if err := validateLogoutURI(in.Client.BackchannelLogoutURI, !s.allowPlainHTTP); err != nil {
		return nil, err
	}

	hint, hintErr := buildLogoutHint(in.Client, in.Subject, in.SessionID)
	if hintErr != nil {
		return nil, hintErr
	}

	token, err := s.tokens.Issue(ctx, hint)
	if err != nil {
		return nil, err
	}

	// Record a pending delivery row (when the repository is
	// wired). Errors on the audit-row write are best-effort: the
	// real POST still proceeds so the RP still gets logged out.
	var deliveryID uuid.UUID
	if s.deliveries != nil {
		id, idErr := uuidgen.NewV7()
		if idErr == nil {
			deliveryID = id
			var sessionPtr, userPtr *uuid.UUID
			if in.SessionID != uuid.Nil {
				cp := in.SessionID
				sessionPtr = &cp
			}
			if in.Subject != uuid.Nil {
				cp := in.Subject
				userPtr = &cp
			}
			_ = s.deliveries.Insert(ctx, &domain.BackchannelLogoutDelivery{
				ID:        id,
				ClientID:  in.Client.ClientID,
				SessionID: sessionPtr,
				UserID:    userPtr,
				LogoutJTI: token.JTI,
				Status:    domain.BackchannelLogoutDeliveryPending,
			})
		}
	}

	// P2-9: the interactive logout request does AT MOST ONE POST and
	// NEVER sleeps. On a transient failure attemptDelivery leaves the row
	// pending with next_attempt_at set, so the async ProcessDueDeliveries
	// driver retries it on the SAME row; the request returns immediately
	// (no 30s/60s backoff sleeps blocking interactive logout). This is
	// attempt #1 of the retry budget.
	status, delivered := s.attemptDelivery(ctx, deliveryID, in.Client.BackchannelLogoutURI, token.LogoutToken, 1)
	res := &DeliverResult{Delivered: delivered, Status: status, URL: in.Client.BackchannelLogoutURI}
	if !delivered {
		return res, ErrBackchannelDeliveryFailed
	}
	return res, nil
}

// buildLogoutHint constructs the logout_token claims for a delivery,
// shared by the interactive Deliver path and the async
// ProcessDueDeliveries driver so both mint an identically-shaped fresh
// token: subject when present, session id only when the client requires
// it, and at least one of the two.
func buildLogoutHint(client *domain.Client, subject, sessionID uuid.UUID) (LogoutTokenInput, error) {
	hint := LogoutTokenInput{Audience: client.ClientID}
	if subject != uuid.Nil {
		hint.Subject = subject
	}
	if client.BackchannelLogoutSessionRequired && sessionID != uuid.Nil {
		hint.SessionID = sessionID
	}
	if hint.Subject == uuid.Nil && hint.SessionID == uuid.Nil {
		return LogoutTokenInput{}, ErrLogoutTokenInvalidInput
	}
	return hint, nil
}

// attemptDelivery performs EXACTLY ONE POST for an already-recorded
// pending row and transitions THAT SAME row.ID based on the outcome. It
// NEVER sleeps and NEVER inserts a row. attemptNumber is the 1-based
// attempt this POST represents (for a due row: row.AttemptCount+1).
//
//   - 2xx                         → MarkDelivered (terminal)
//   - transient + attempts remain → MarkAttemptFailed (row stays pending,
//     next_attempt_at scheduled for the async driver)
//   - permanent (4xx≠408/429) OR attempts exhausted → MarkPermanentlyFailed
//
// Returns the upstream status and whether it was delivered.
func (s *BackchannelLogoutService) attemptDelivery(ctx context.Context, deliveryID uuid.UUID, dst, tokenJWT string, attemptNumber int) (int, bool) {
	form := url.Values{}
	form.Set("logout_token", tokenJWT)
	body := form.Encode()

	status, err := s.postOnce(ctx, dst, body)
	if err == nil {
		if s.deliveries != nil && deliveryID != uuid.Nil {
			_ = s.deliveries.MarkDelivered(ctx, deliveryID, status, s.now().UTC())
		}
		return status, true
	}
	s.recordFailedAttempt(ctx, deliveryID, status, sanitiseError(err), attemptNumber)
	return status, false
}

// recordFailedAttempt transitions a row after a failed attempt: terminal
// (MarkPermanentlyFailed) on a permanent status OR when the retry budget
// is exhausted (attemptNumber >= maxAttempts); otherwise it stays pending
// with next_attempt_at scheduled (MarkAttemptFailed). Bounding on
// attemptNumber guarantees a due row reaches a terminal state — and
// leaves the due queue — after at most maxAttempts total attempts.
func (s *BackchannelLogoutService) recordFailedAttempt(ctx context.Context, deliveryID uuid.UUID, status int, errMsg string, attemptNumber int) {
	if s.deliveries == nil || deliveryID == uuid.Nil {
		return
	}
	if !shouldRetryStatus(status) || attemptNumber >= s.maxAttempts {
		_ = s.deliveries.MarkPermanentlyFailed(ctx, deliveryID, status, errMsg, s.now().UTC())
		return
	}
	nextAttempt := s.now().UTC().Add(s.retryBackoff * time.Duration(attemptNumber))
	_ = s.deliveries.MarkAttemptFailed(ctx, deliveryID, attemptNumber, status, errMsg, nextAttempt, s.now().UTC())
}

// postOnce performs a single POST attempt. Returns the upstream
// status (0 on network error) and an error when the attempt
// should be considered a failure.
func (s *BackchannelLogoutService) postOnce(ctx context.Context, dst, body string) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, dst, strings.NewReader(body))
	if err != nil {
		return 0, ErrBackchannelDeliveryFailed
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, ErrBackchannelDeliveryFailed
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, ErrBackchannelDeliveryFailed
	}
	return resp.StatusCode, nil
}

// shouldRetryStatus reports whether a status code is worth
// retrying. Network errors (status 0) are retried; 5xx is
// retried; 408 + 429 are retried (RP back-pressure); 4xx
// otherwise is permanent.
func shouldRetryStatus(status int) bool {
	if status == 0 {
		return true
	}
	if status >= 500 {
		return true
	}
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// sanitiseError truncates the supplied error message + strips
// CR/LF so a misbehaving RP cannot inject log-shape characters
// into our durable rows.
func sanitiseError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 256 {
		msg = msg[:256]
	}
	return msg
}

// DeleteExpiredDeliveries prunes old delivery rows. Used by the
// cleanup driver.
func (s *BackchannelLogoutService) DeleteExpiredDeliveries(ctx context.Context, retention time.Duration) (int64, error) {
	if s.deliveries == nil {
		return 0, nil
	}
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}
	return s.deliveries.DeleteOlderThan(ctx, s.now().UTC().Add(-retention))
}

// BackchannelDueProcessorClientLookup is the seam ProcessDueDeliveries
// consults to resolve a row's client_id back to a *domain.Client
// so a fresh logout_token can be minted.
type BackchannelDueProcessorClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// WithDueProcessorClientLookup wires the client lookup used by
// ProcessDueDeliveries. Without it wired, the processor is a
// no-op — there is no safe way to reissue a logout_token without a
// resolved client.
func (s *BackchannelLogoutService) WithDueProcessorClientLookup(c BackchannelDueProcessorClientLookup) *BackchannelLogoutService {
	s.dueProcessorClients = c
	return s
}

// ProcessDueDeliveries loads up to `limit` pending rows whose
// `next_attempt_at` has elapsed, resolves each row's client, mints
// a fresh logout_token (the original token bytes are NEVER
// replayed), and re-attempts delivery. Returns the count of rows
// processed.
//
// The processor is bounded per-tick: at most `limit` rows are
// touched even when the queue is larger. The cleanup driver calls
// this once per tick.
//
// When the client lookup is not wired, returns 0.
func (s *BackchannelLogoutService) ProcessDueDeliveries(ctx context.Context, limit int) (int, error) {
	if s.deliveries == nil || s.dueProcessorClients == nil {
		return 0, nil
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.deliveries.ListDueForRetry(ctx, s.now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, row := range rows {
		client, lookupErr := s.dueProcessorClients.GetClientByClientID(ctx, row.ClientID)
		if lookupErr != nil || client == nil || client.BackchannelLogoutURI == "" {
			// Client gone or has no URI — flip to permanently
			// failed so the row stops occupying the queue.
			_ = s.deliveries.MarkPermanentlyFailed(ctx, row.ID, 0, "client_gone_or_no_uri", s.now().UTC())
			processed++
			continue
		}
		if err := validateLogoutURI(client.BackchannelLogoutURI, !s.allowPlainHTTP); err != nil {
			_ = s.deliveries.MarkPermanentlyFailed(ctx, row.ID, 0, sanitiseError(err), s.now().UTC())
			processed++
			continue
		}
		var subject, sessionID uuid.UUID
		if row.UserID != nil {
			subject = *row.UserID
		}
		if row.SessionID != nil {
			sessionID = *row.SessionID
		}
		hint, hintErr := buildLogoutHint(client, subject, sessionID)
		if hintErr != nil {
			_ = s.deliveries.MarkPermanentlyFailed(ctx, row.ID, 0, "invalid_token_input", s.now().UTC())
			processed++
			continue
		}
		// This POST is attempt (row.AttemptCount+1) of the budget.
		attemptNumber := row.AttemptCount + 1
		// Mint a FRESH logout_token — the original token bytes are NEVER
		// replayed. A mint failure is treated as a failed attempt (status 0
		// = transient) so it is bounded by maxAttempts rather than looping.
		token, tokenErr := s.tokens.Issue(ctx, hint)
		if tokenErr != nil {
			s.recordFailedAttempt(ctx, row.ID, 0, "token_mint_failed", attemptNumber)
			processed++
			continue
		}
		// EXACTLY ONE POST on THIS SAME row.ID — no new row, no Deliver(),
		// no synchronous retry loop. attemptDelivery transitions the row.
		_, _ = s.attemptDelivery(ctx, row.ID, client.BackchannelLogoutURI, token.LogoutToken, attemptNumber)
		processed++
	}
	return processed, nil
}

// validateLogoutURI rejects fragments and non-HTTPS schemes.
// requireHTTPS=false lets the test harness override locally.
func validateLogoutURI(raw string, requireHTTPS bool) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ErrBackchannelHTTPSRequired
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return ErrBackchannelURIHasFragment
	}
	if requireHTTPS && u.Scheme != "https" {
		return ErrBackchannelHTTPSRequired
	}
	return nil
}
