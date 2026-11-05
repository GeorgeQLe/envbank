// Package vercelworkflow connects Vercel to the existing encrypted rollout,
// automation-policy and MCP boundaries. It never accepts tool-supplied values.
package vercelworkflow

import (
	"errors"
	"sort"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

func ScopeForManifest(document *contract.Document) (vercel.Scope, error) {
	if document == nil {
		return vercel.Scope{}, errors.New("Vercel manifest is required")
	}
	target, ok := document.Manifest.Targets["vercel"]
	if !ok || len(target.Services) != 1 {
		return vercel.Scope{}, errors.New("Vercel target requires one environment service")
	}
	service, ok := target.Services["environment"]
	if !ok || len(service.Absent) != 0 || len(service.Variables) == 0 {
		return vercel.Scope{}, errors.New("Vercel target requires explicit variables; deletion is not supported")
	}
	scope := vercel.Scope{TeamID: target.TeamID, ProjectID: target.ProjectID, Environment: target.Environment, GitBranch: target.GitBranch, CustomEnvironmentID: target.CustomEnvironmentID}
	if err := scope.Validate(); err != nil {
		return vercel.Scope{}, errors.New("Vercel scope is invalid")
	}
	if target.EnvironmentID != "" && target.EnvironmentID != scope.Target().EnvironmentID {
		return vercel.Scope{}, errors.New("Vercel environment ID conflicts with scope")
	}
	if service.ID != "" && service.ID != scope.Fingerprint() {
		return vercel.Scope{}, errors.New("Vercel environment service ID conflicts with scope")
	}
	for name, variable := range service.Variables {
		if !vercel.ValidSecretName(name) {
			return vercel.Scope{}, errors.New("Vercel vault binding name is not permitted")
		}
		for _, prefix := range []string{"NEXT_PUBLIC_", "PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "GATSBY_", "EXPO_PUBLIC_"} {
			if strings.HasPrefix(name, prefix) {
				return vercel.Scope{}, errors.New("Vercel vault bindings cannot use client-exposed names")
			}
		}
		if variable.Source != "record" {
			return vercel.Scope{}, errors.New("Vercel secret variables require vault records")
		}
	}
	return scope, nil
}

func PlanInput(document *contract.Document, snapshot bundle.Snapshot, revision int64) (rollout.PlanInput, error) {
	scope, err := ScopeForManifest(document)
	if err != nil {
		return rollout.PlanInput{}, err
	}
	if revision < 1 || snapshot.Validate() != nil || snapshot.Bundle != document.Manifest.Bundle || snapshot.ManifestDigest != document.Digest {
		return rollout.PlanInput{}, errors.New("Vercel plan requires a current prepared snapshot")
	}
	variables := document.Manifest.Targets["vercel"].Services["environment"].Variables
	ordered := make([]string, 0, len(variables))
	for name := range variables {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	input := rollout.PlanInput{Bundle: snapshot.Bundle, ManifestDigest: document.Digest, SnapshotRevision: revision, Kind: rollout.PlanKindBindingNames, Target: rollout.TargetBinding{ProjectID: scope.Target().ProjectID, EnvironmentID: scope.Target().EnvironmentID, ServiceIDs: scope.Target().ServiceIDs}}
	for _, name := range ordered {
		record := variables[name].Record
		r := snapshot.RecordRevisions[record]
		if r < 1 {
			return rollout.PlanInput{}, errors.New("Vercel snapshot lacks a required record")
		}
		input.Names = append(input.Names, rollout.PlannedName{Service: "environment", ServiceID: scope.Fingerprint(), Name: name, Desired: "present", State: "unverifiable", Record: record, ExpectedRecordRevision: r})
		input.Actions = append(input.Actions, rollout.Action{ID: "environment/" + name, Operation: "upsert", Service: "environment", ServiceID: scope.Fingerprint(), Name: name, Record: record, ExpectedRecordRevision: r})
	}
	return input, nil
}
