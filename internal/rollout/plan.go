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
	MaxActions  = 512
)

type PlanKind string

const (
	PlanKindNamesOnly    PlanKind = "names-only"
	PlanKindBindingNames PlanKind = "binding-names"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var evidencePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type ProviderPlan struct {
	Version          int           `json:"version"`
	Bundle           string        `json:"bundle"`
	ManifestDigest   string        `json:"manifest_digest"`
	SnapshotRevision int64         `json:"snapshot_revision"`
	Provider         string        `json:"provider"`
	ProviderIdentity string        `json:"provider_identity"`
	ProviderRevision string        `json:"provider_revision,omitempty"`
	Target           TargetBinding `json:"target"`
	Kind             PlanKind      `json:"kind,omitempty"`
	Names            []PlannedName `json:"names,omitempty"`
	Actions          []Action      `json:"actions"`
	CreatedAt        string        `json:"created_at"`
	ExpiresAt        string        `json:"expires_at"`
	Digest           string        `json:"digest"`
}

// PlannedName is a names-and-revisions-only statement of desired provider
// state. State is unverifiable when the provider cannot safely expose names
// without also returning values.
type PlannedName struct {
	Service                string `json:"service"`
	ServiceID              string `json:"service_id"`
	Name                   string `json:"name"`
	Desired                string `json:"desired"`
	State                  string `json:"state"`
	Record                 string `json:"record,omitempty"`
	ExpectedRecordRevision int64  `json:"expected_record_revision,omitempty"`
}

type TargetBinding struct {
	ProjectID     string            `json:"project_id"`
	EnvironmentID string            `json:"environment_id"`
	ServiceIDs    map[string]string `json:"service_ids"`
}

type Action struct {
	ID          string `json:"id"`
	Operation   string `json:"operation"`
	Service     string `json:"service"`
	ServiceID   string `json:"service_id"`
	Name        string `json:"name"`
	Record      string `json:"record,omitempty"`
	ValueSource string `json:"value_source,omitempty"`
	// PublicValue is permitted only for manifest values already classified as
	// public constants. Secret and imported values must remain record-backed.
	PublicValue            string `json:"public_value,omitempty"`
	ExpectedRecordRevision int64  `json:"expected_record_revision,omitempty"`
}

// ID returns the opaque local identifier used to store and later apply the
// plan. The digest already binds every plan field, so no second identifier is
// required.
func (plan ProviderPlan) ID() string { return plan.Digest }

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
	if plan.ProviderRevision != "" && !evidencePattern.MatchString(plan.ProviderRevision) {
		return errors.New("provider plan revision evidence is invalid")
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
	if now.Before(created) {
		return errors.New("provider plan is not yet valid")
	}
	if plan.Target.ProjectID == "" || plan.Target.EnvironmentID == "" || plan.Target.ServiceIDs == nil {
		return errors.New("provider plan target binding is incomplete")
	}
	if plan.Kind != "" && plan.Kind != PlanKindNamesOnly && plan.Kind != PlanKindBindingNames {
		return errors.New("provider plan kind is invalid")
	}
	if plan.Kind == PlanKindNamesOnly || plan.Kind == PlanKindBindingNames {
		if len(plan.Names) == 0 || len(plan.Names) > MaxActions || len(plan.Actions) > MaxActions {
			return fmt.Errorf("names-only provider plan must contain between 1 and %d names", MaxActions)
		}
		if err := validateNames(plan.Names, plan.Target); err != nil {
			return err
		}
	} else if len(plan.Actions) == 0 || len(plan.Actions) > MaxActions || len(plan.Names) != 0 {
		return fmt.Errorf("provider plan must contain between 1 and %d actions", MaxActions)
	}
	seenActions := make(map[string]struct{}, len(plan.Actions))
	seenTargets := make(map[string]struct{}, len(plan.Actions))
	for index, action := range plan.Actions {
		if action.ID == "" || action.Operation == "" || action.Service == "" ||
			action.ServiceID == "" || action.Name == "" {
			return fmt.Errorf("provider plan action %d is incomplete", index)
		}
		if _, exists := seenActions[action.ID]; exists {
			return fmt.Errorf("provider plan action %d has a duplicate ID", index)
		}
		seenActions[action.ID] = struct{}{}
		targetKey := action.Service + "\x00" + action.Name
		if _, exists := seenTargets[targetKey]; exists {
			return fmt.Errorf("provider plan action %d duplicates a variable target", index)
		}
		seenTargets[targetKey] = struct{}{}
		if err := validateAction(index, action, plan.Target); err != nil {
			return err
		}
	}
	if plan.Kind == PlanKindNamesOnly || plan.Kind == PlanKindBindingNames {
		if err := validateNamedActions(plan.Kind, plan.Names, plan.Actions); err != nil {
			return err
		}
	}
	want, err := plan.ComputeDigest()
	if err != nil || plan.Digest != want {
		return errors.New("provider plan digest is invalid")
	}
	return nil
}

func validateNamedActions(kind PlanKind, names []PlannedName, actions []Action) error {
	byTarget := make(map[string]PlannedName, len(names))
	for _, item := range names {
		byTarget[item.Service+"\x00"+item.Name] = item
	}
	for index, action := range actions {
		item, exists := byTarget[action.Service+"\x00"+action.Name]
		upsert := item.Desired == "present" && action.Operation == "upsert" &&
			action.Record == item.Record && action.ExpectedRecordRevision == item.ExpectedRecordRevision
		revoke := kind == PlanKindBindingNames && item.Desired == "absent" && action.Operation == "revoke"
		if !exists || !upsert && !revoke {
			return fmt.Errorf("names-only provider plan action %d does not match a desired-present name", index)
		}
	}
	return nil
}

func validateNames(names []PlannedName, target TargetBinding) error {
	seen := make(map[string]struct{}, len(names))
	for index, item := range names {
		if item.Service == "" || item.ServiceID == "" || item.Name == "" ||
			target.ServiceIDs[item.Service] != item.ServiceID ||
			(item.Desired != "present" && item.Desired != "absent") ||
			(item.State != "unverifiable" && item.State != "present" && item.State != "absent") {
			return fmt.Errorf("names-only provider plan entry %d is invalid", index)
		}
		key := item.Service + "\x00" + item.Name
		if _, exists := seen[key]; exists {
			return fmt.Errorf("names-only provider plan entry %d is duplicated", index)
		}
		seen[key] = struct{}{}
		if item.Desired == "absent" && (item.Record != "" || item.ExpectedRecordRevision != 0) {
			return fmt.Errorf("names-only provider plan entry %d has unexpected record state", index)
		}
		if item.Record == "" && item.ExpectedRecordRevision != 0 ||
			item.Record != "" && item.ExpectedRecordRevision < 1 {
			return fmt.Errorf("names-only provider plan entry %d has an invalid record revision", index)
		}
	}
	return nil
}

func validateAction(index int, action Action, target TargetBinding) error {
	if action.ID == "" || action.Operation == "" || action.Service == "" ||
		action.ServiceID == "" || action.Name == "" {
		return fmt.Errorf("provider plan action %d is incomplete", index)
	}
	switch action.Operation {
	case "create", "update", "upsert", "revoke":
	default:
		return fmt.Errorf("provider plan action %d has an invalid operation", index)
	}
	if bound := target.ServiceIDs[action.Service]; bound != action.ServiceID {
		return fmt.Errorf("provider plan action %d has an invalid service binding", index)
	}
	if action.Operation != "revoke" {
		recordBacked := (action.ValueSource == "" || action.ValueSource == "record") &&
			action.Record != "" && action.ExpectedRecordRevision > 0 && action.PublicValue == ""
		publicConstant := action.ValueSource == "public-constant" &&
			action.Record == "" && action.ExpectedRecordRevision == 0
		if !recordBacked && !publicConstant {
			return fmt.Errorf("provider plan action %d has an invalid value source", index)
		}
	}
	if action.Operation == "revoke" && (action.Record != "" || action.ValueSource != "" || action.PublicValue != "" || action.ExpectedRecordRevision != 0) {
		return fmt.Errorf("provider plan action %d has unexpected record state", index)
	}
	return nil
}
