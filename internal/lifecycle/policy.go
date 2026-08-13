package lifecycle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const PolicyVersion = 1

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type TargetPolicy struct {
	Provider      string `json:"provider"`
	ProjectID     string `json:"project_id"`
	EnvironmentID string `json:"environment_id"`
}

// AutomationPolicy is encrypted as a vault object. Signature covers every
// field except Signature and binds the approval to one device and manifest.
type AutomationPolicy struct {
	Version            int               `json:"version"`
	ID                 string            `json:"id"`
	VaultID            string            `json:"vault_id"`
	Bundle             string            `json:"bundle"`
	ManifestDigest     string            `json:"manifest_digest"`
	Environment        string            `json:"environment"`
	ProviderIdentities map[string]string `json:"provider_identities"`
	CredentialClasses  []string          `json:"credential_classes"`
	Operations         []string          `json:"operations"`
	Targets            []TargetPolicy    `json:"targets"`
	Schedule           string            `json:"schedule"`
	HealthChecks       []string          `json:"health_checks"`
	GracePeriod        string            `json:"grace_period"`
	Rollback           string            `json:"rollback"`
	RetryBudget        int               `json:"retry_budget"`
	ExpiresAt          string            `json:"expires_at"`
	ApprovingDevice    string            `json:"approving_device"`
	PublicKey          []byte            `json:"public_key"`
	Signature          []byte            `json:"signature"`
}

func (policy AutomationPolicy) signingBytes() ([]byte, error) {
	policy.Signature = nil
	return json.Marshal(policy)
}

func (policy AutomationPolicy) Digest() (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (policy *AutomationPolicy) Sign(private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("policy signing key is invalid")
	}
	policy.PublicKey = append([]byte(nil), private.Public().(ed25519.PublicKey)...)
	raw, err := policy.signingBytes()
	if err != nil {
		return err
	}
	policy.Signature = ed25519.Sign(private, raw)
	return nil
}

func (policy AutomationPolicy) Validate(now time.Time) error {
	if policy.Version != PolicyVersion || policy.ID == "" || policy.VaultID == "" || policy.Bundle == "" || !digestPattern.MatchString(policy.ManifestDigest) ||
		policy.Environment == "" || len(policy.ProviderIdentities) == 0 || len(policy.CredentialClasses) == 0 || len(policy.Operations) == 0 || len(policy.Targets) == 0 ||
		policy.Schedule == "" || len(policy.HealthChecks) == 0 || policy.Rollback == "" || policy.RetryBudget < 1 || policy.RetryBudget > 3 || policy.ApprovingDevice == "" {
		return errors.New("automation policy binding is incomplete")
	}
	expires, err := time.Parse(time.RFC3339, policy.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339) != policy.ExpiresAt || !now.Before(expires) || expires.After(now.Add(90*24*time.Hour)) {
		return errors.New("automation policy expiry is invalid")
	}
	grace, err := time.ParseDuration(policy.GracePeriod)
	if err != nil || grace <= 0 || policy.Environment == "production" && grace < 24*time.Hour || policy.Environment != "production" && grace < 15*time.Minute {
		return errors.New("automation policy grace period is invalid")
	}
	if len(policy.PublicKey) != ed25519.PublicKeySize || len(policy.Signature) != ed25519.SignatureSize {
		return errors.New("automation policy signature is invalid")
	}
	raw, err := policy.signingBytes()
	if err != nil || !ed25519.Verify(ed25519.PublicKey(policy.PublicKey), raw, policy.Signature) {
		return errors.New("automation policy signature is invalid")
	}
	for _, operation := range policy.Operations {
		if operation != "create" && operation != "stage" && operation != "activate" && operation != "verify" && operation != "rollback" && operation != "revoke" {
			return fmt.Errorf("automation policy operation %q is invalid", operation)
		}
	}
	if duplicateStrings(policy.Operations) || duplicateStrings(policy.CredentialClasses) {
		return errors.New("automation policy contains duplicate capabilities")
	}
	seenTargets := map[string]bool{}
	for _, target := range policy.Targets {
		key := target.Provider + "\x00" + target.ProjectID + "\x00" + target.EnvironmentID
		if target.Provider == "" || target.ProjectID == "" || target.EnvironmentID == "" || seenTargets[key] {
			return errors.New("automation policy target binding is invalid")
		}
		seenTargets[key] = true
	}
	return nil
}

func (policy AutomationPolicy) Authorizes(binding AuthorizationBinding, now time.Time) error {
	if err := policy.Validate(now); err != nil {
		return err
	}
	if policy.VaultID != binding.VaultID || policy.Bundle != binding.Bundle || policy.ManifestDigest != binding.ManifestDigest || policy.Environment != binding.Environment ||
		policy.ProviderIdentities[binding.Provider] != binding.ProviderIdentity || !stringContains(policy.CredentialClasses, binding.CredentialClass) || !stringContains(policy.Operations, binding.Operation) {
		return errors.New("automation policy does not authorize this operation")
	}
	for _, target := range policy.Targets {
		if target.Provider == binding.Target.Provider && target.ProjectID == binding.Target.ProjectID && target.EnvironmentID == binding.Target.EnvironmentID {
			return nil
		}
	}
	return errors.New("automation policy target binding changed")
}

type AuthorizationBinding struct {
	VaultID, Bundle, ManifestDigest, Environment, Provider, ProviderIdentity, CredentialClass, Operation string
	Target                                                                                               TargetPolicy
}

type Evidence struct {
	Sequence       int64  `json:"sequence"`
	OperationID    string `json:"operation_id"`
	Stage          string `json:"stage"`
	Code           string `json:"code"`
	At             string `json:"at"`
	PreviousDigest string `json:"previous_digest"`
	Digest         string `json:"digest"`
	Device         string `json:"device"`
	Signature      []byte `json:"signature"`
}

func NewEvidence(previous *Evidence, operationID, stage, code, device string, now time.Time, private ed25519.PrivateKey) (Evidence, error) {
	evidence := Evidence{Sequence: 1, OperationID: operationID, Stage: stage, Code: code, At: now.UTC().Format(time.RFC3339), Device: device}
	if previous != nil {
		evidence.Sequence = previous.Sequence + 1
		evidence.PreviousDigest = previous.Digest
	}
	if operationID == "" || stage == "" || device == "" || len(private) != ed25519.PrivateKeySize {
		return Evidence{}, errors.New("evidence binding is invalid")
	}
	raw, _ := json.Marshal(evidence)
	sum := sha256.Sum256(raw)
	evidence.Digest = hex.EncodeToString(sum[:])
	signing, _ := evidence.signingBytes()
	evidence.Signature = ed25519.Sign(private, signing)
	return evidence, nil
}

func (evidence Evidence) signingBytes() ([]byte, error) {
	copy := evidence
	copy.Signature = nil
	return json.Marshal(copy)
}

func VerifyEvidenceChain(chain []Evidence, public ed25519.PublicKey) error {
	var previous string
	for index, evidence := range chain {
		if evidence.Sequence != int64(index+1) || evidence.PreviousDigest != previous || !digestPattern.MatchString(evidence.Digest) {
			return errors.New("evidence chain is invalid")
		}
		copy := evidence
		copy.Digest = ""
		copy.Signature = nil
		raw, _ := json.Marshal(copy)
		sum := sha256.Sum256(raw)
		if evidence.Digest != hex.EncodeToString(sum[:]) {
			return errors.New("evidence digest is invalid")
		}
		signing, _ := evidence.signingBytes()
		if !ed25519.Verify(public, signing, evidence.Signature) {
			return errors.New("evidence signature is invalid")
		}
		previous = evidence.Digest
	}
	return nil
}

func stringContains(values []string, wanted string) bool {
	ordered := sorted(values)
	index := sort.SearchStrings(ordered, wanted)
	return index < len(ordered) && ordered[index] == wanted
}
func sorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
func duplicateStrings(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
