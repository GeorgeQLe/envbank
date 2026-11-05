package ownerinput

import (
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// The agent-request budget stays well inside the host's 120 s tool-call
// limit and leaves room for a Touch ID prompt.
func TestAgentRequestBudget(t *testing.T) {
	if agentRequestTimeout != 110*time.Second || approval.MinPromptTime != 15*time.Second {
		t.Fatalf("budget %v, min prompt %v", agentRequestTimeout, approval.MinPromptTime)
	}
}
