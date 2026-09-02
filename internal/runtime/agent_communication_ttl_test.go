package runtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestResolveAgentCommunicationTokenTTL(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == AgentCommunicationTokenTTLEnv {
				return v
			}
			return ""
		}
	}
	assert.Equal(t, service.DefaultAgentCommunicationTokenTTL, resolveAgentCommunicationTokenTTL(nil))
	assert.Equal(t, service.DefaultAgentCommunicationTokenTTL, resolveAgentCommunicationTokenTTL(env("")))
	assert.Equal(t, 2*time.Minute, resolveAgentCommunicationTokenTTL(env("2m")))
	assert.Equal(t, service.MaxAgentCommunicationTokenTTL, resolveAgentCommunicationTokenTTL(env("1h")), "hard maximum clamps")
	assert.Equal(t, service.DefaultAgentCommunicationTokenTTL, resolveAgentCommunicationTokenTTL(env("junk")))
	assert.Equal(t, service.DefaultAgentCommunicationTokenTTL, resolveAgentCommunicationTokenTTL(env("-1s")))
}
