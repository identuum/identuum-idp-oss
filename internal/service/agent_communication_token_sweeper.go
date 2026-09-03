package service

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// AgentCommunicationTokenSweeper prunes expired issued-token rows
// (agent_communication_tokens, AYGHU-4). It satisfies ExpiredRowSweeper for
// the revocation cleanup ticker.
type AgentCommunicationTokenSweeper struct {
	repo repository.AgentCommunicationTokenRepository
	now  func() time.Time
}

// NewAgentCommunicationTokenSweeper wires the sweeper (P-018: a nil repo is
// a recorded startup fault, never a panic).
func NewAgentCommunicationTokenSweeper(report *lifecycle.StartupReport, repo repository.AgentCommunicationTokenRepository) *AgentCommunicationTokenSweeper {
	if repo == nil {
		report.Fatal("NewAgentCommunicationTokenSweeper", "service: NewAgentCommunicationTokenSweeper requires a non-nil AgentCommunicationTokenRepository")
	}
	return &AgentCommunicationTokenSweeper{repo: repo, now: time.Now}
}

// DeleteExpired implements ExpiredRowSweeper.
func (s *AgentCommunicationTokenSweeper) DeleteExpired(ctx context.Context) (int64, error) {
	if s == nil || s.repo == nil {
		return 0, nil
	}
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}
