package railway

import (
	"errors"
	"fmt"
	"sort"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

var siftCutServices = [...]string{"postgres", "migrator", "api", "web"}

func SiftCutServiceNames() []string {
	return append([]string(nil), siftCutServices[:]...)
}

// BindingRequestForManifest constrains Milestone 7 to the exact four-service
// SiftCut target. Optional IDs in the manifest are treated as assertions, not
// hints.
func BindingRequestForManifest(document *contract.Document) (BindingRequest, error) {
	if document == nil {
		return BindingRequest{}, errors.New("Railway manifest is required")
	}
	target, exists := document.Manifest.Targets[ProviderName]
	if !exists {
		return BindingRequest{}, errors.New("manifest has no Railway target")
	}
	if len(target.Services) != len(siftCutServices) {
		return BindingRequest{}, errors.New("Railway target must contain exactly postgres, migrator, api, and web")
	}
	services := make(map[string]string, len(siftCutServices))
	for _, name := range siftCutServices {
		service, exists := target.Services[name]
		if !exists {
			return BindingRequest{}, errors.New("Railway target must contain exactly postgres, migrator, api, and web")
		}
		services[name] = service.ID
	}
	return BindingRequest{Project: target.Project, ProjectID: target.ProjectID,
		Environment: target.Environment, EnvironmentID: target.EnvironmentID, Services: services}, nil
}

// BuildNamesOnlyInput creates a deterministic names-only plan. Every remote
// state remains unverifiable because the adapter makes no variable query.
// Locally available record values and explicitly public constants become
// upsert actions; unresolved public imports and intended absence do not.
func BuildNamesOnlyInput(document *contract.Document, snapshot bundle.Snapshot,
	snapshotRevision int64, target provider.Target) (rollout.PlanInput, error) {
	request, err := BindingRequestForManifest(document)
	if err != nil {
		return rollout.PlanInput{}, err
	}
	if snapshotRevision < 1 || snapshot.Validate() != nil || snapshot.Bundle != document.Manifest.Bundle ||
		snapshot.ManifestDigest != document.Digest {
		return rollout.PlanInput{}, errors.New("Railway plan requires the current prepared bundle snapshot")
	}
	if target.ProjectID == "" || target.EnvironmentID == "" || len(target.ServiceIDs) != len(request.Services) {
		return rollout.PlanInput{}, errors.New("Railway target binding is incomplete")
	}
	seenIDs := make(map[string]struct{}, len(target.ServiceIDs))
	for name, expectedID := range request.Services {
		if target.ServiceIDs[name] == "" || expectedID != "" && target.ServiceIDs[name] != expectedID {
			return rollout.PlanInput{}, errors.New("Railway service binding does not match the manifest")
		}
		if _, exists := seenIDs[target.ServiceIDs[name]]; exists {
			return rollout.PlanInput{}, errors.New("Railway service binding contains a duplicate ID")
		}
		seenIDs[target.ServiceIDs[name]] = struct{}{}
	}

	manifestTarget := document.Manifest.Targets[ProviderName]
	services := SiftCutServiceNames()
	sort.Slice(services, func(i, j int) bool {
		left, right := manifestTarget.Services[services[i]], manifestTarget.Services[services[j]]
		if left.Order == right.Order {
			return services[i] < services[j]
		}
		return left.Order < right.Order
	})
	names := make([]rollout.PlannedName, 0)
	actions := make([]rollout.Action, 0)
	for _, serviceName := range services {
		service := manifestTarget.Services[serviceName]
		variableNames := make([]string, 0, len(service.Variables))
		for name := range service.Variables {
			variableNames = append(variableNames, name)
		}
		sort.Strings(variableNames)
		for _, name := range variableNames {
			variable := service.Variables[name]
			item := rollout.PlannedName{Service: serviceName, ServiceID: target.ServiceIDs[serviceName],
				Name: name, Desired: "present", State: "unverifiable"}
			if variable.Source == "record" {
				item.Record = variable.Record
				item.ExpectedRecordRevision = snapshot.RecordRevisions[variable.Record]
				if item.ExpectedRecordRevision < 1 {
					return rollout.PlanInput{}, fmt.Errorf("Railway plan record %s is missing from the snapshot", variable.Record)
				}
			}
			names = append(names, item)
			if variable.Source == "record" || variable.Source == "constant" {
				action := rollout.Action{ID: serviceName + "/" + name, Operation: "upsert",
					Service: serviceName, ServiceID: target.ServiceIDs[serviceName], Name: name,
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
			names = append(names, rollout.PlannedName{Service: serviceName,
				ServiceID: target.ServiceIDs[serviceName], Name: name,
				Desired: "absent", State: "unverifiable"})
		}
	}
	return rollout.PlanInput{Bundle: document.Manifest.Bundle, ManifestDigest: document.Digest,
		SnapshotRevision: snapshotRevision, Kind: rollout.PlanKindNamesOnly,
		Target: rollout.TargetBinding{ProjectID: target.ProjectID, EnvironmentID: target.EnvironmentID,
			ServiceIDs: cloneServiceIDs(target.ServiceIDs)}, Names: names, Actions: actions}, nil
}

func cloneServiceIDs(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, id := range values {
		result[name] = id
	}
	return result
}
