package runtime

import (
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// AgentCommunicationTokenTTLEnv configures the participant-token lifetime
// (AYGHU-3) as a Go duration. Unset, empty or unparsable → the service
// default (5 min); anything above the hard maximum (15 min) is clamped by
// the service.
const AgentCommunicationTokenTTLEnv = "IDENTUUM_IDP_AGENT_COMMUNICATION_TOKEN_TTL"

func resolveAgentCommunicationTokenTTL(getenv func(string) string) time.Duration {
	if getenv == nil {
		return service.DefaultAgentCommunicationTokenTTL
	}
	raw := strings.TrimSpace(getenv(AgentCommunicationTokenTTLEnv))
	if raw == "" {
		return service.DefaultAgentCommunicationTokenTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return service.DefaultAgentCommunicationTokenTTL
	}
	if d > service.MaxAgentCommunicationTokenTTL {
		return service.MaxAgentCommunicationTokenTTL
	}
	return d
}
