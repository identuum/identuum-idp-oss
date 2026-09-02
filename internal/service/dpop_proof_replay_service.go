package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ErrDPoPReplayInvalidInput — Mark was called without a thumbprint or jti.
var ErrDPoPReplayInvalidInput = errors.New("service: dpop replay mark requires jkt and jti")

// DPoPProofReplayMarker is the seam the token issuer uses: Mark answers
// whether this (key, jti) pair is seen for the first time.
type DPoPProofReplayMarker interface {
	Mark(ctx context.Context, jkt, jti string) (firstUse bool, err error)
}

// DPoPProofReplayServiceOptions carries the row retention.
type DPoPProofReplayServiceOptions struct {
	// Retention is how long a (jkt, jti) row is kept. A proof is only
	// accepted within ±dpopProofClockSkew of its iat, so anything beyond
	// twice the skew can never be replayed; the default keeps a margin.
	Retention time.Duration
}

// DPoPProofReplayService records DPoP proof identifiers for the token
// endpoint. It is separate from ClientAssertionReplayService on purpose.
type DPoPProofReplayService struct {
	repo      repository.DPoPProofReplayRepository
	retention time.Duration
	now       func() time.Time
}

// NewDPoPProofReplayService wires the service (P-018: nil repo is a
// recorded startup fault, never a panic).
func NewDPoPProofReplayService(report *lifecycle.StartupReport, repo repository.DPoPProofReplayRepository, opts DPoPProofReplayServiceOptions) *DPoPProofReplayService {
	if repo == nil {
		report.Fatal("NewDPoPProofReplayService", "service: NewDPoPProofReplayService requires a non-nil DPoPProofReplayRepository")
	}
	retention := opts.Retention
	if retention <= 0 {
		retention = 5 * time.Minute
	}
	return &DPoPProofReplayService{repo: repo, retention: retention, now: time.Now}
}

func hashDPoPJTI(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:])
}

// Mark records the proof identifier; false means the pair was already
// seen (replay). A store error is returned as-is for the caller to surface
// as unavailability.
func (s *DPoPProofReplayService) Mark(ctx context.Context, jkt, jti string) (bool, error) {
	jkt = strings.TrimSpace(jkt)
	jti = strings.TrimSpace(jti)
	if jkt == "" || jti == "" {
		return false, ErrDPoPReplayInvalidInput
	}
	return s.repo.Insert(ctx, jkt, hashDPoPJTI(jti), s.now().UTC().Add(s.retention))
}

// DeleteExpired prunes rows past their retention (ExpiredRowSweeper).
func (s *DPoPProofReplayService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}
