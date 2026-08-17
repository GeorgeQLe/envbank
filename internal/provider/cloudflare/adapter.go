// Package cloudflare implements the Cloudflare Workers version/deployment
// boundary without ever returning secret values from provider inspection.
package cloudflare

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	ProviderName      = "cloudflare"
	CredentialService = "envbank.cloudflare.api-token.v1"
)

type Target struct {
	AccountID  string
	ZoneID     string
	ScriptName string
}

type Snapshot struct {
	AccountID      string
	ZoneID         string
	ScriptName     string
	PriorVersionID string
	BindingNames   []string
}

type StageRequest struct {
	Target         Target
	PriorVersionID string
	Secrets        map[string][]byte
	RemovedNames   []string
}

// VersionAPI is deliberately version-oriented: Stage uploads an undeployed
// version, while Deploy is called only by explicit promotion or rollback.
type VersionAPI interface {
	Identity(context.Context, string) error
	Inspect(context.Context, Target) (Snapshot, error)
	Stage(context.Context, StageRequest) (string, error)
	VersionBindingNames(context.Context, Target, string) ([]string, error)
	Deploy(context.Context, Target, string, bool) (string, error)
}

type Adapter struct {
	API    VersionAPI
	Target Target
	Now    func() time.Time
}

func (adapter *Adapter) Capabilities() provider.Capabilities {
	return provider.Capabilities{Create: true, ReadMetadata: true, Update: true,
		Validate: true, Revoke: true, SupportsIdempotentWrite: false, SupportsMaskedPresence: true}
}

func (adapter *Adapter) Identity(ctx context.Context) (provider.Identity, error) {
	if err := adapter.ready(); err != nil {
		return provider.Identity{}, err
	}
	if err := adapter.API.Identity(ctx, adapter.Target.AccountID); err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{Provider: ProviderName, ID: adapter.Target.AccountID}, nil
}

func (adapter *Adapter) Inspect(ctx context.Context, target provider.Target) (provider.MetadataState, error) {
	if err := adapter.validateTarget(target); err != nil {
		return provider.MetadataState{}, err
	}
	snapshot, err := adapter.API.Inspect(ctx, adapter.Target)
	if err != nil {
		return provider.MetadataState{}, err
	}
	if snapshot.AccountID != adapter.Target.AccountID || snapshot.ZoneID != adapter.Target.ZoneID ||
		snapshot.ScriptName != adapter.Target.ScriptName {
		return provider.MetadataState{}, errors.New("Cloudflare target identity mismatch")
	}
	variables := make(map[string]provider.VariableMetadata, len(snapshot.BindingNames))
	for _, name := range snapshot.BindingNames {
		variables[name] = provider.VariableMetadata{Presence: provider.PresencePresent}
	}
	return provider.MetadataState{Target: target, Revision: snapshot.PriorVersionID,
		Variables: map[string]map[string]provider.VariableMetadata{adapter.Target.ScriptName: variables}}, nil
}

func (*Adapter) Write(context.Context, provider.WriteRequest) (provider.WriteEvidence, error) {
	return provider.WriteEvidence{}, errors.New("Cloudflare bindings must be staged atomically")
}

func (adapter *Adapter) Stage(ctx context.Context, requests []provider.WriteRequest) (provider.WriteEvidence, error) {
	if err := adapter.ready(); err != nil {
		return provider.WriteEvidence{}, err
	}
	if len(requests) == 0 {
		return provider.WriteEvidence{}, errors.New("Cloudflare stage requires at least one binding")
	}
	snapshot, err := adapter.API.Inspect(ctx, adapter.Target)
	if err != nil {
		return provider.WriteEvidence{}, err
	}
	if snapshot.PriorVersionID == "" || snapshot.AccountID != adapter.Target.AccountID ||
		snapshot.ZoneID != adapter.Target.ZoneID || snapshot.ScriptName != adapter.Target.ScriptName {
		return provider.WriteEvidence{}, errors.New("Cloudflare stage target identity mismatch")
	}
	secrets := make(map[string][]byte, len(requests))
	defer func() {
		for name, value := range secrets {
			clear(value)
			delete(secrets, name)
		}
	}()
	for _, request := range requests {
		if err := adapter.validateTarget(request.Target); err != nil ||
			(request.Operation != "upsert" && request.Operation != "revoke") ||
			request.Service != adapter.Target.ScriptName || request.ServiceID != adapter.Target.ScriptName ||
			request.Name == "" {
			return provider.WriteEvidence{}, errors.New("invalid Cloudflare atomic binding request")
		}
		if _, duplicate := secrets[request.Name]; duplicate {
			return provider.WriteEvidence{}, errors.New("duplicate Cloudflare binding name")
		}
		if request.Operation == "revoke" {
			continue
		}
		if err := request.ViewSecret(func(value []byte) error {
			secrets[request.Name] = append([]byte(nil), value...)
			return nil
		}); err != nil {
			return provider.WriteEvidence{}, err
		}
	}
	removed := make([]string, 0)
	for _, request := range requests {
		if request.Operation == "revoke" {
			removed = append(removed, request.Name)
		}
	}
	sort.Strings(removed)
	versionID, err := adapter.API.Stage(ctx, StageRequest{Target: adapter.Target,
		PriorVersionID: snapshot.PriorVersionID, Secrets: secrets, RemovedNames: removed})
	if err != nil {
		return provider.WriteEvidence{}, err
	}
	if strings.TrimSpace(versionID) == "" || len(versionID) > 128 {
		return provider.WriteEvidence{}, errors.New("Cloudflare returned an invalid version ID")
	}
	return provider.WriteEvidence{ProviderOperationID: versionID, CommittedAt: adapter.now()}, nil
}

func (adapter *Adapter) Verify(ctx context.Context, request provider.VerifyRequest) (provider.VerifyEvidence, error) {
	if err := adapter.validateTarget(request.Target); err != nil || request.Service != adapter.Target.ScriptName ||
		request.ServiceID != adapter.Target.ScriptName || request.Name == "" || request.ProviderOperationID == "" {
		return provider.VerifyEvidence{}, errors.New("invalid Cloudflare version verification request")
	}
	names, err := adapter.API.VersionBindingNames(ctx, adapter.Target, request.ProviderOperationID)
	if err != nil {
		return provider.VerifyEvidence{}, err
	}
	sort.Strings(names)
	index := sort.SearchStrings(names, request.Name)
	if index >= len(names) || names[index] != request.Name {
		return provider.VerifyEvidence{Result: provider.VerificationLimited,
			Presence: provider.PresenceAbsent, VerifiedAt: adapter.now(), Reason: "binding-absent"}, nil
	}
	return provider.VerifyEvidence{Result: provider.VerificationVerified,
		Presence: provider.PresencePresent, VerifiedAt: adapter.now()}, nil
}

func (adapter *Adapter) Promote(ctx context.Context, versionID string) (string, error) {
	if versionID == "" {
		return "", errors.New("Cloudflare staged version is required")
	}
	return adapter.API.Deploy(ctx, adapter.Target, versionID, false)
}

func (adapter *Adapter) Rollback(ctx context.Context, priorVersionID string) (string, error) {
	if priorVersionID == "" {
		return "", errors.New("Cloudflare prior version is required")
	}
	return adapter.API.Deploy(ctx, adapter.Target, priorVersionID, true)
}

func (adapter *Adapter) validateTarget(target provider.Target) error {
	if err := adapter.ready(); err != nil {
		return err
	}
	if target.ProjectID != adapter.Target.AccountID || target.EnvironmentID != adapter.Target.ZoneID ||
		len(target.ServiceIDs) != 1 || target.ServiceIDs[adapter.Target.ScriptName] != adapter.Target.ScriptName {
		return errors.New("Cloudflare target binding does not match account, zone, and script")
	}
	return nil
}

func (adapter *Adapter) ready() error {
	if adapter == nil || adapter.API == nil || adapter.Target.AccountID == "" ||
		adapter.Target.ZoneID == "" || adapter.Target.ScriptName == "" {
		return errors.New("Cloudflare adapter is not configured")
	}
	return nil
}

func (adapter *Adapter) now() string {
	now := time.Now
	if adapter.Now != nil {
		now = adapter.Now
	}
	return now().UTC().Truncate(time.Second).Format(time.RFC3339)
}
