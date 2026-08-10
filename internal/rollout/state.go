package rollout

import (
	"errors"
	"fmt"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const OperationVersion = 1

type OperationStatus string

const (
	StatusDraft          OperationStatus = "draft"
	StatusPrepared       OperationStatus = "prepared"
	StatusPlanned        OperationStatus = "planned"
	StatusConfirmed      OperationStatus = "confirmed"
	StatusWriting        OperationStatus = "writing"
	StatusRetryable      OperationStatus = "retryable"
	StatusReconciliation OperationStatus = "reconciliation-required"
	StatusWritten        OperationStatus = "written"
	StatusVerifying      OperationStatus = "verifying"
	StatusReady          OperationStatus = "ready-to-deploy"
	StatusLimited        OperationStatus = "limited"
	StatusFailed         OperationStatus = "failed"
)

type ActionStatus string

const (
	ActionPending   ActionStatus = "pending"
	ActionInFlight  ActionStatus = "in_flight"
	ActionCommitted ActionStatus = "committed"
	ActionVerified  ActionStatus = "verified"
	ActionLimited   ActionStatus = "limited"
)

// Operation is encrypted as a rollout-operation vault object. It contains
// names and provider evidence, but never secret values or provider bodies.
type Operation struct {
	Version          int               `json:"version"`
	ID               string            `json:"id"`
	PlanID           string            `json:"plan_id"`
	PlanDigest       string            `json:"plan_digest"`
	Bundle           string            `json:"bundle"`
	ManifestDigest   string            `json:"manifest_digest"`
	SnapshotRevision int64             `json:"snapshot_revision"`
	Provider         string            `json:"provider"`
	ProviderIdentity string            `json:"provider_identity"`
	Target           TargetBinding     `json:"target"`
	Status           OperationStatus   `json:"status"`
	Actions          []OperationAction `json:"actions"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
}

type OperationAction struct {
	Action         Action                   `json:"action"`
	Status         ActionStatus             `json:"status"`
	Attempts       int                      `json:"attempts"`
	WriteKey       string                   `json:"write_key"`
	LastAttemptAt  string                   `json:"last_attempt_at,omitempty"`
	WriteEvidence  *provider.WriteEvidence  `json:"write_evidence,omitempty"`
	VerifyEvidence *provider.VerifyEvidence `json:"verify_evidence,omitempty"`
	LastError      *provider.Error          `json:"last_error,omitempty"`
}

func (operation Operation) Validate() error {
	if operation.Version != OperationVersion || operation.ID == "" || operation.PlanID == "" ||
		operation.PlanDigest != operation.PlanID || !digestPattern.MatchString(operation.PlanDigest) ||
		operation.Bundle == "" || !digestPattern.MatchString(operation.ManifestDigest) ||
		operation.SnapshotRevision < 1 || operation.Provider == "" || operation.ProviderIdentity == "" {
		return errors.New("rollout operation identity is invalid")
	}
	if !validOperationStatus(operation.Status) || len(operation.Actions) == 0 || len(operation.Actions) > MaxActions {
		return errors.New("rollout operation status is invalid")
	}
	if operation.Target.ProjectID == "" || operation.Target.EnvironmentID == "" || operation.Target.ServiceIDs == nil {
		return errors.New("rollout operation target binding is incomplete")
	}
	created, err := canonicalTime(operation.CreatedAt)
	if err != nil {
		return errors.New("rollout operation creation time is invalid")
	}
	updated, err := canonicalTime(operation.UpdatedAt)
	if err != nil || updated.Before(created) {
		return errors.New("rollout operation update time is invalid")
	}
	seen := make(map[string]struct{}, len(operation.Actions))
	for index, item := range operation.Actions {
		if _, exists := seen[item.Action.ID]; exists {
			return fmt.Errorf("rollout operation action %d is duplicated", index)
		}
		seen[item.Action.ID] = struct{}{}
		if err := validateAction(index, item.Action, operation.Target); err != nil {
			return fmt.Errorf("rollout operation action %d does not match its target", index)
		}
		if item.Action.ID == "" || !digestPattern.MatchString(item.WriteKey) ||
			!validActionStatus(item.Status) || item.Attempts < 0 {
			return fmt.Errorf("rollout operation action %d is invalid", index)
		}
		if item.LastError != nil && item.LastError.Validate() != nil {
			return fmt.Errorf("rollout operation action %d error is invalid", index)
		}
		if item.LastAttemptAt != "" {
			if _, err := canonicalTime(item.LastAttemptAt); err != nil || item.Attempts == 0 {
				return fmt.Errorf("rollout operation action %d attempt is invalid", index)
			}
		}
		if item.Status == ActionPending && item.WriteEvidence != nil ||
			(item.Status == ActionVerified || item.Status == ActionLimited) && item.VerifyEvidence == nil ||
			(item.Status == ActionCommitted || item.Status == ActionVerified || item.Status == ActionLimited) && item.WriteEvidence == nil {
			return fmt.Errorf("rollout operation action %d evidence is invalid", index)
		}
		if item.WriteEvidence != nil && item.WriteEvidence.Validate() != nil {
			return fmt.Errorf("rollout operation action %d write evidence is invalid", index)
		}
		if item.VerifyEvidence != nil {
			if item.VerifyEvidence.Validate() != nil ||
				item.Status == ActionVerified && item.VerifyEvidence.Result != provider.VerificationVerified ||
				item.Status == ActionLimited && item.VerifyEvidence.Result != provider.VerificationLimited {
				return fmt.Errorf("rollout operation action %d verification is invalid", index)
			}
		}
	}
	if operation.Status == StatusReady || operation.Status == StatusLimited {
		limited := false
		for index, item := range operation.Actions {
			if item.Status != ActionVerified && item.Status != ActionLimited {
				return fmt.Errorf("terminal rollout operation action %d is incomplete", index)
			}
			limited = limited || item.Status == ActionLimited
		}
		if limited != (operation.Status == StatusLimited) {
			return errors.New("terminal rollout operation status is inconsistent")
		}
	}
	return nil
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("non-canonical timestamp")
	}
	return parsed, nil
}

func validOperationStatus(status OperationStatus) bool {
	switch status {
	case StatusDraft, StatusPrepared, StatusPlanned, StatusConfirmed, StatusWriting,
		StatusRetryable, StatusReconciliation, StatusWritten, StatusVerifying, StatusReady, StatusLimited,
		StatusFailed:
		return true
	default:
		return false
	}
}

func validActionStatus(status ActionStatus) bool {
	switch status {
	case ActionPending, ActionInFlight, ActionCommitted, ActionVerified, ActionLimited:
		return true
	default:
		return false
	}
}
