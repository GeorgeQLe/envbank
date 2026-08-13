package lifecycle

import (
	"errors"
	"time"
)

const OperationVersion = 1

// Operation retains both sides of a rotation until the grace period and
// revocation complete. Secret values are represented only by record revisions
// and opaque upstream identifiers.
type Operation struct {
	Version                int          `json:"version"`
	ID                     string       `json:"id"`
	PolicyID               string       `json:"policy_id"`
	PolicyDigest           string       `json:"policy_digest"`
	VaultID                string       `json:"vault_id"`
	Bundle                 string       `json:"bundle"`
	ManifestDigest         string       `json:"manifest_digest"`
	Provider               string       `json:"provider"`
	ProviderIdentity       string       `json:"provider_identity"`
	Target                 TargetPolicy `json:"target"`
	CredentialClass        string       `json:"credential_class"`
	DestinationRecord      string       `json:"destination_record"`
	PreviousRecordRevision int64        `json:"previous_record_revision"`
	NewRecordRevision      int64        `json:"new_record_revision,omitempty"`
	PreviousCredentialID   string       `json:"previous_credential_id"`
	NewCredentialID        string       `json:"new_credential_id,omitempty"`
	HealthEvidenceDigest   string       `json:"health_evidence_digest,omitempty"`
	State                  State        `json:"state"`
	Attempts               int          `json:"attempts"`
	GraceEndsAt            string       `json:"grace_ends_at,omitempty"`
	CreatedAt              string       `json:"created_at"`
	UpdatedAt              string       `json:"updated_at"`
}

func (operation Operation) Validate() error {
	if operation.Version != OperationVersion || operation.ID == "" || operation.PolicyID == "" || !digestPattern.MatchString(operation.PolicyDigest) || operation.VaultID == "" || operation.Bundle == "" ||
		!digestPattern.MatchString(operation.ManifestDigest) || operation.Provider == "" || operation.ProviderIdentity == "" || operation.CredentialClass == "" || operation.DestinationRecord == "" ||
		operation.PreviousRecordRevision < 1 || operation.PreviousCredentialID == "" || operation.Target.Provider == "" || operation.Target.ProjectID == "" || operation.Target.EnvironmentID == "" || operation.Attempts < 0 || operation.Attempts > 3 {
		return errors.New("lifecycle operation binding is invalid")
	}
	created, err := time.Parse(time.RFC3339, operation.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339) != operation.CreatedAt {
		return errors.New("lifecycle operation creation time is invalid")
	}
	updated, err := time.Parse(time.RFC3339, operation.UpdatedAt)
	if err != nil || updated.UTC().Format(time.RFC3339) != operation.UpdatedAt || updated.Before(created) {
		return errors.New("lifecycle operation update time is invalid")
	}
	if operation.NewRecordRevision != 0 && operation.NewRecordRevision <= operation.PreviousRecordRevision {
		return errors.New("new record revision must advance the previous revision")
	}
	if operation.State != StatePlanned && operation.NewRecordRevision == 0 && operation.State != StateAcquiring && operation.State != StateRetryable && operation.State != StateTerminalFailure {
		return errors.New("lifecycle operation lost the new record revision")
	}
	if (operation.State == StateHealthy || operation.State == StateGracePeriod || operation.State == StateRevoking || operation.State == StateComplete) && !digestPattern.MatchString(operation.HealthEvidenceDigest) {
		return errors.New("lifecycle operation health evidence is invalid")
	}
	if operation.GraceEndsAt != "" {
		grace, err := time.Parse(time.RFC3339, operation.GraceEndsAt)
		if err != nil || grace.Before(created) {
			return errors.New("lifecycle operation grace time is invalid")
		}
	}
	return nil
}

func (operation *Operation) Move(to State, now time.Time) error {
	if operation == nil {
		return errors.New("lifecycle operation is nil")
	}
	if err := Transition(operation.State, to); err != nil {
		return err
	}
	operation.State = to
	operation.UpdatedAt = now.UTC().Format(time.RFC3339)
	return operation.Validate()
}

// RevocationAllowed rechecks every immutable binding immediately before the
// destructive upstream operation.
func (operation Operation) RevocationAllowed(binding AuthorizationBinding, recordRevision int64, healthEvidenceDigest string, now time.Time, policy AutomationPolicy) error {
	policyDigest, err := policy.Digest()
	if err != nil || operation.Validate() != nil || operation.State != StateRevoking || operation.NewRecordRevision != recordRevision || operation.HealthEvidenceDigest != healthEvidenceDigest || operation.PolicyDigest != policyDigest || operation.VaultID != binding.VaultID || operation.Bundle != binding.Bundle || operation.ManifestDigest != binding.ManifestDigest || operation.Provider != binding.Provider || operation.ProviderIdentity != binding.ProviderIdentity || operation.CredentialClass != binding.CredentialClass || operation.Target != binding.Target {
		return errors.New("revocation safety evidence changed")
	}
	if operation.GraceEndsAt == "" {
		return errors.New("revocation grace period is missing")
	}
	grace, err := time.Parse(time.RFC3339, operation.GraceEndsAt)
	if err != nil || now.Before(grace) {
		return errors.New("revocation grace period has not elapsed")
	}
	return policy.Authorizes(binding, now)
}
