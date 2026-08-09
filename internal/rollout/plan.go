// Package rollout defines provider-neutral encrypted plan state.
package rollout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	PlanVersion = 1
	PlanTTL     = 15 * time.Minute
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type ProviderPlan struct {
	Version          int           `json:"version"`
	Bundle           string        `json:"bundle"`
	ManifestDigest   string        `json:"manifest_digest"`
	SnapshotRevision int64         `json:"snapshot_revision"`
	Provider         string        `json:"provider"`
	ProviderIdentity string        `json:"provider_identity"`
	Target           TargetBinding `json:"target"`
	Actions          []Action      `json:"actions"`
	CreatedAt        string        `json:"created_at"`
	ExpiresAt        string        `json:"expires_at"`
	Digest           string        `json:"digest"`
}

type TargetBinding struct {
	ProjectID     string            `json:"project_id"`
	EnvironmentID string            `json:"environment_id"`
	ServiceIDs    map[string]string `json:"service_ids"`
}

type Action struct {
	ID                     string `json:"id"`
	Operation              string `json:"operation"`
	Service                string `json:"service"`
	ServiceID              string `json:"service_id"`
	Name                   string `json:"name"`
	Record                 string `json:"record,omitempty"`
	ExpectedRecordRevision int64  `json:"expected_record_revision,omitempty"`
}

// ComputeDigest hashes the canonical JSON representation with Digest empty.
// Action order is intentionally significant.
func (plan ProviderPlan) ComputeDigest() (string, error) {
	plan.Digest = ""
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (plan ProviderPlan) Validate(now time.Time) error {
	if plan.Version != PlanVersion {
		return fmt.Errorf("unsupported provider plan version %d", plan.Version)
	}
	if plan.Bundle == "" || !digestPattern.MatchString(plan.ManifestDigest) ||
		plan.SnapshotRevision < 1 || plan.Provider == "" || plan.ProviderIdentity == "" {
		return errors.New("provider plan identity is invalid")
	}
	created, err := time.Parse(time.RFC3339, plan.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339) != plan.CreatedAt {
		return errors.New("provider plan creation time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339) != plan.ExpiresAt ||
		!expires.Equal(created.Add(PlanTTL)) {
		return errors.New("provider plan expiry is invalid")
	}
	if !now.Before(expires) {
		return errors.New("provider plan has expired")
	}
	if plan.Target.ProjectID == "" || plan.Target.EnvironmentID == "" || plan.Target.ServiceIDs == nil {
		return errors.New("provider plan target binding is incomplete")
	}
	seenActions := make(map[string]struct{}, len(plan.Actions))
	for index, action := range plan.Actions {
		if action.ID == "" || action.Operation == "" || action.Service == "" ||
			action.ServiceID == "" || action.Name == "" {
			return fmt.Errorf("provider plan action %d is incomplete", index)
		}
		if _, exists := seenActions[action.ID]; exists {
			return fmt.Errorf("provider plan action %d has a duplicate ID", index)
		}
		seenActions[action.ID] = struct{}{}
		if bound := plan.Target.ServiceIDs[action.Service]; bound != action.ServiceID {
			return fmt.Errorf("provider plan action %d has an invalid service binding", index)
		}
		if action.Record != "" && action.ExpectedRecordRevision < 1 {
			return fmt.Errorf("provider plan action %d has an invalid record revision", index)
		}
	}
	want, err := plan.ComputeDigest()
	if err != nil || plan.Digest != want {
		return errors.New("provider plan digest is invalid")
	}
	return nil
}
