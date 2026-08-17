package cloudflare

import (
	"errors"
	"fmt"
	"sort"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

func TargetForManifest(document *contract.Document) (Target, provider.Target, error) {
	if document == nil {
		return Target{}, provider.Target{}, errors.New("Cloudflare manifest is required")
	}
	target, exists := document.Manifest.Targets[ProviderName]
	if !exists {
		return Target{}, provider.Target{}, errors.New("manifest has no Cloudflare target")
	}
	if target.ProjectID == "" || target.EnvironmentID == "" || len(target.Services) != 1 {
		return Target{}, provider.Target{}, errors.New("Cloudflare target requires exact account, zone, and Worker identities")
	}
	var serviceName string
	for name, service := range target.Services {
		if service.ID == "" || service.ID != name {
			return Target{}, provider.Target{}, errors.New("Cloudflare Worker service name and immutable script ID must match")
		}
		serviceName = name
	}
	bound := Target{AccountID: target.ProjectID, ZoneID: target.EnvironmentID, ScriptName: serviceName}
	if err := validateCloudflareTarget(bound); err != nil {
		return Target{}, provider.Target{}, err
	}
	return bound, provider.Target{ProjectID: bound.AccountID, EnvironmentID: bound.ZoneID,
		ServiceIDs: map[string]string{bound.ScriptName: bound.ScriptName}}, nil
}

func BuildPlanInput(document *contract.Document, snapshot bundle.Snapshot, snapshotRevision int64,
	target provider.Target) (rollout.PlanInput, error) {
	bound, expected, err := TargetForManifest(document)
	if err != nil {
		return rollout.PlanInput{}, err
	}
	if snapshotRevision < 1 || snapshot.Validate() != nil || snapshot.Bundle != document.Manifest.Bundle ||
		snapshot.ManifestDigest != document.Digest {
		return rollout.PlanInput{}, errors.New("Cloudflare plan requires the current prepared bundle snapshot")
	}
	if target.ProjectID != expected.ProjectID || target.EnvironmentID != expected.EnvironmentID ||
		len(target.ServiceIDs) != 1 || target.ServiceIDs[bound.ScriptName] != bound.ScriptName {
		return rollout.PlanInput{}, errors.New("Cloudflare target binding does not match the manifest")
	}
	service := document.Manifest.Targets[ProviderName].Services[bound.ScriptName]
	variableNames := make([]string, 0, len(service.Variables))
	for name := range service.Variables {
		variableNames = append(variableNames, name)
	}
	sort.Strings(variableNames)
	names := make([]rollout.PlannedName, 0, len(variableNames)+len(service.Absent))
	actions := make([]rollout.Action, 0, len(variableNames)+len(service.Absent))
	for _, name := range variableNames {
		variable := service.Variables[name]
		item := rollout.PlannedName{Service: bound.ScriptName, ServiceID: bound.ScriptName,
			Name: name, Desired: "present"}
		if variable.Source == "record" {
			item.Record = variable.Record
			item.ExpectedRecordRevision = snapshot.RecordRevisions[variable.Record]
			if item.ExpectedRecordRevision < 1 {
				return rollout.PlanInput{}, fmt.Errorf("Cloudflare plan record %s is missing from the snapshot", variable.Record)
			}
		}
		names = append(names, item)
		if variable.Source == "record" || variable.Source == "constant" {
			action := rollout.Action{ID: bound.ScriptName + "/" + name, Operation: "upsert",
				Service: bound.ScriptName, ServiceID: bound.ScriptName, Name: name,
				Record: item.Record, ExpectedRecordRevision: item.ExpectedRecordRevision}
			if variable.Source == "constant" {
				action.ValueSource = "public-constant"
				action.PublicValue = variable.Value
			}
			actions = append(actions, action)
		}
	}
	absent := append([]string(nil), service.Absent...)
	sort.Strings(absent)
	for _, name := range absent {
		names = append(names, rollout.PlannedName{Service: bound.ScriptName, ServiceID: bound.ScriptName,
			Name: name, Desired: "absent"})
		actions = append(actions, rollout.Action{ID: bound.ScriptName + "/" + name, Operation: "revoke",
			Service: bound.ScriptName, ServiceID: bound.ScriptName, Name: name})
	}
	return rollout.PlanInput{Bundle: document.Manifest.Bundle, ManifestDigest: document.Digest,
		SnapshotRevision: snapshotRevision, Kind: rollout.PlanKindBindingNames,
		Target: rollout.TargetBinding{ProjectID: target.ProjectID, EnvironmentID: target.EnvironmentID,
			ServiceIDs: map[string]string{bound.ScriptName: bound.ScriptName}}, Names: names, Actions: actions}, nil
}
