package lifecycle

import (
	"errors"
	"fmt"
	"time"
)

type State string

const (
	StatePlanned                State = "planned"
	StateAcquiring              State = "acquiring"
	StateStored                 State = "stored"
	StateStaging                State = "staging"
	StateStaged                 State = "staged"
	StateActivating             State = "activating"
	StateHealthy                State = "healthy"
	StateGracePeriod            State = "grace-period"
	StateRevoking               State = "revoking"
	StateComplete               State = "complete"
	StateRetryable              State = "retryable"
	StateReconciliationRequired State = "reconciliation-required"
	StateRollingBack            State = "rolling-back"
	StateRolledBack             State = "rolled-back"
	StateQuarantined            State = "quarantined-new-credential"
	StateTerminalFailure        State = "terminal-failure"
)

var transitions = map[State]map[State]bool{
	StatePlanned: {StateAcquiring: true, StateTerminalFailure: true}, StateAcquiring: {StateStored: true, StateRetryable: true, StateReconciliationRequired: true, StateTerminalFailure: true},
	StateStored: {StateStaging: true, StateRollingBack: true}, StateStaging: {StateStaged: true, StateRetryable: true, StateRollingBack: true}, StateStaged: {StateActivating: true, StateRollingBack: true},
	StateActivating: {StateHealthy: true, StateRetryable: true, StateRollingBack: true}, StateHealthy: {StateGracePeriod: true, StateRollingBack: true}, StateGracePeriod: {StateRevoking: true, StateRollingBack: true},
	StateRevoking: {StateComplete: true, StateRetryable: true, StateReconciliationRequired: true}, StateRetryable: {StateAcquiring: true, StateStaging: true, StateActivating: true, StateRevoking: true, StateTerminalFailure: true},
	StateReconciliationRequired: {StateAcquiring: true, StateRevoking: true, StateRollingBack: true, StateTerminalFailure: true}, StateRollingBack: {StateRolledBack: true, StateTerminalFailure: true}, StateRolledBack: {StateQuarantined: true},
}

func CanTransition(from, to State) bool { return transitions[from][to] }
func Transition(from, to State) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("invalid lifecycle transition %s -> %s", from, to)
	}
	return nil
}

type Lease struct {
	Bundle     string `json:"bundle"`
	Owner      string `json:"owner"`
	AcquiredAt string `json:"acquired_at"`
	ExpiresAt  string `json:"expires_at"`
}

func (lease Lease) Validate(now time.Time) error {
	if lease.Bundle == "" || lease.Owner == "" {
		return errors.New("lifecycle lease binding is invalid")
	}
	acquired, err := time.Parse(time.RFC3339, lease.AcquiredAt)
	if err != nil || acquired.UTC().Format(time.RFC3339) != lease.AcquiredAt {
		return errors.New("lifecycle lease acquisition time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, lease.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339) != lease.ExpiresAt || !expires.After(acquired) || expires.After(acquired.Add(15*time.Minute)) {
		return errors.New("lifecycle lease expiry is invalid")
	}
	_ = now
	return nil
}
