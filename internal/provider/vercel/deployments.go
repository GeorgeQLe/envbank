package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	// MetaOperationKey and MetaScopeKey are attached to every deployment that
	// Redeploy creates so uncertain creates can be reconciled.
	MetaOperationKey = "envbankOperationId"
	MetaScopeKey     = "envbankScope"
	MetaSourceKey    = "envbankSourceDeploymentId"

	findWindow          = 14 * 24 * time.Hour
	findPageLimit       = 100
	findMaxPages        = 20
	maxProductionAlias  = 25
	maxDeploymentMeta   = 256
	readyStateReady     = "READY"
	substateStaged      = "STAGED"
	substatePromoted    = "PROMOTED"
	substateRolling     = "ROLLING"
	codeNotFound        = "DEPLOYMENT_NOT_FOUND"
	codeScopeMismatch   = "DEPLOYMENT_SCOPE_MISMATCH"
	codeOperationScope  = "OPERATION_SCOPE_MISMATCH"
	codeCreatedMismatch = "CREATED_DEPLOYMENT_MISMATCH"
)

var timestampPattern = regexp.MustCompile(`^[0-9]{1,16}$`)

// Deployment is validated, non-secret deployment metadata. Environment is
// "preview", "production" or "custom". No upstream error or free-form body
// data is ever placed here.
type Deployment struct {
	ID                 string `json:"id"`
	ProjectID          string `json:"project_id"`
	TeamID             string `json:"team_id"`
	Environment        string `json:"environment"`
	GitBranch          string `json:"git_branch,omitempty"`
	URL                string `json:"url,omitempty"`
	ReadyState         string `json:"ready_state"`
	CommitSHA          string `json:"commit_sha,omitempty"`
	SourceDeploymentID string `json:"source_deployment_id,omitempty"`
	Prebuilt           bool   `json:"prebuilt,omitempty"`
}

type deploymentRecord struct {
	Deployment
	substate    string
	commitSHA   string
	operationID string
	scopeMarker string
}

type gitSourceWire struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

type deploymentWire struct {
	Prebuilt      bool    `json:"prebuilt"`
	ID            string  `json:"id"`
	ProjectID     string  `json:"projectId"`
	OwnerID       string  `json:"ownerId"`
	Target        *string `json:"target"`
	ReadyState    string  `json:"readyState"`
	ReadySubstate string  `json:"readySubstate"`
	URL           string  `json:"url"`
	Team          *struct {
		ID string `json:"id"`
	} `json:"team"`
	Meta              map[string]json.RawMessage `json:"meta"`
	GitSource         *gitSourceWire             `json:"gitSource"`
	CustomEnvironment *struct {
		ID string `json:"id"`
	} `json:"customEnvironment"`
}

var readyStates = map[string]struct{}{"BLOCKED": {}, "BUILDING": {}, "CANCELED": {}, "DELETED": {},
	"ERROR": {}, "INITIALIZING": {}, "QUEUED": {}, readyStateReady: {}}

// Deployment reads one deployment and proves it belongs to this exact
// team/project/environment (and branch, for branch-scoped preview).
func (adapter *Adapter) Deployment(ctx context.Context, id string) (Deployment, error) {
	if !deploymentIDPattern.MatchString(id) {
		return Deployment{}, safeError("deployment", "INVALID_DEPLOYMENT_ID", provider.RetryNever)
	}
	record, err := adapter.fetchDeployment(ctx, "deployment", id)
	if err != nil {
		return Deployment{}, err
	}
	return record.Deployment, nil
}

// Redeploy creates one new deployment from sourceID in this exact scope. It
// pins the source commit (withLatestCommit=false), forces a fresh build so new
// variables apply, never assigns custom domains (so production builds are
// created staged, not promoted) and tags the build with operationID for
// FindDeployment reconciliation. It refuses a reused operationID. A create is
// never retried; on an ambiguous error, reconcile with FindDeployment.
func (adapter *Adapter) Redeploy(ctx context.Context, sourceID, operationID string) (Deployment, error) {
	return adapter.redeployTracked(ctx, sourceID, operationID)
}
func (adapter *Adapter) redeployTracked(ctx context.Context, sourceID, operationID string) (result Deployment, err error) {
	sent := false
	defer func() {
		if err != nil && !sent {
			err = markNotSent(err)
		}
	}()
	return adapter.redeploy(ctx, sourceID, operationID, &sent)
}
func (adapter *Adapter) redeploy(ctx context.Context, sourceID, operationID string, sent *bool) (Deployment, error) {
	const operation = "redeploy"
	if !deploymentIDPattern.MatchString(sourceID) || !operationIDPattern.MatchString(operationID) {
		return Deployment{}, safeError(operation, "INVALID_REDEPLOY", provider.RetryNever)
	}
	project, err := adapter.verifiedProject(ctx, operation)
	if err != nil {
		return Deployment{}, err
	}
	source, err := adapter.fetchDeployment(ctx, operation, sourceID)
	if err != nil {
		return Deployment{}, err
	}
	if source.ReadyState != readyStateReady {
		return Deployment{}, safeError(operation, "SOURCE_NOT_READY", provider.RetryNever)
	}
	if source.Prebuilt || source.CommitSHA == "" {
		return Deployment{}, safeError(operation, "SOURCE_NOT_REBUILDABLE", provider.RetryNever)
	}
	if _, err := adapter.findDeployment(ctx, operation, operationID); err == nil {
		return Deployment{}, safeError(operation, "OPERATION_ALREADY_EXISTS", provider.RetryNever)
	} else if !hasCode(err, codeNotFound) {
		return Deployment{}, err
	}

	request := struct {
		Name                      string            `json:"name"`
		Project                   string            `json:"project"`
		DeploymentID              string            `json:"deploymentId"`
		Target                    string            `json:"target,omitempty"`
		CustomEnvironmentSlugOrID string            `json:"customEnvironmentSlugOrId,omitempty"`
		WithLatestCommit          bool              `json:"withLatestCommit"`
		AutoAssignCustomDomains   bool              `json:"autoAssignCustomDomains"`
		Meta                      map[string]string `json:"meta"`
	}{Name: project.Name, Project: adapter.scope.ProjectID, DeploymentID: sourceID,
		WithLatestCommit: false, AutoAssignCustomDomains: false,
		Meta: map[string]string{MetaOperationKey: operationID, MetaScopeKey: adapter.scope.Fingerprint(), MetaSourceKey: sourceID}}
	switch adapter.scope.Environment {
	case EnvironmentProduction:
		request.Target = EnvironmentProduction
	case EnvironmentCustom:
		request.CustomEnvironmentSlugOrID = adapter.scope.CustomEnvironmentID
	}
	// Preview omits target: Vercel's default target is preview, and the source
	// has already been proven to be a preview deployment of this scope.
	body, err := json.Marshal(request)
	if err != nil {
		return Deployment{}, safeError(operation, "ENCODE_FAILED", provider.RetryNever)
	}
	var wire deploymentWire
	err = adapter.send(ctx, apiCall{operation: operation, method: http.MethodPost, path: "/v13/deployments",
		query: url.Values{"forceNew": {"1"}}, body: body, mutation: true, attempted: sent}, func(raw []byte) error {
		if err := json.Unmarshal(raw, &wire); err != nil || !deploymentIDPattern.MatchString(wire.ID) {
			return safeError(operation, "UNCONFIRMED_DEPLOYMENT", provider.RetryAmbiguous)
		}
		return nil
	})
	if err != nil {
		return Deployment{}, err
	}
	// The create response is only checked for consistency; the fresh read
	// below is the full ownership/scope/commit proof.
	createdOperation, createdScope, markersOK := markers(wire.Meta)
	createdEnvironment, createdCustom, environmentOK := deploymentEnvironment(wire)
	if wire.ProjectID != adapter.scope.ProjectID || (wire.OwnerID != "" && wire.OwnerID != adapter.scope.TeamID) ||
		!markersOK || (createdOperation != "" && createdOperation != operationID) ||
		(createdScope != "" && createdScope != adapter.scope.Fingerprint()) || !environmentOK ||
		createdEnvironment != adapter.scope.Environment || createdCustom != adapter.scope.CustomEnvironmentID {
		return Deployment{}, safeError(operation, codeCreatedMismatch, provider.RetryNever)
	}
	fresh, err := adapter.fetchDeployment(ctx, operation, wire.ID)
	if err != nil {
		if hasCode(err, codeScopeMismatch) || hasCode(err, "DEPLOYMENT_METADATA_INVALID") {
			return Deployment{}, safeError(operation, codeCreatedMismatch, provider.RetryNever)
		}
		return Deployment{}, safeError(operation, "CREATED_UNVERIFIED", provider.RetryAmbiguous)
	}
	if fresh.operationID != operationID || fresh.scopeMarker != adapter.scope.Fingerprint() {
		return Deployment{}, safeError(operation, codeCreatedMismatch, provider.RetryNever)
	}
	if adapter.scope.Environment == EnvironmentProduction &&
		(wire.ReadySubstate == substatePromoted || fresh.substate == substatePromoted || fresh.substate == substateRolling) {
		return Deployment{}, safeError(operation, "UNEXPECTED_PROMOTION", provider.RetryNever)
	}
	if source.commitSHA != "" {
		switch {
		case fresh.commitSHA == "":
			return Deployment{}, safeError(operation, "SOURCE_COMMIT_UNVERIFIED", provider.RetryNever)
		case fresh.commitSHA != source.commitSHA:
			return Deployment{}, safeError(operation, "SOURCE_COMMIT_DRIFT", provider.RetryNever)
		}
	}
	if source.GitBranch != "" && fresh.GitBranch != source.GitBranch {
		return Deployment{}, safeError(operation, "SOURCE_BRANCH_DRIFT", provider.RetryNever)
	}
	return fresh.Deployment, nil
}

// Promote directly promotes a READY, STAGED production deployment of this
// exact project. Preview/custom scopes are refused, so a preview build is
// never promoted (Vercel would rebuild it with production variables).
// Acceptance is asynchronous; confirm with CurrentDeployment.
func (adapter *Adapter) Promote(ctx context.Context, id string) error {
	sent := false
	return adapter.promoteTracked(ctx, id, &sent)
}
func (adapter *Adapter) promoteTracked(ctx context.Context, id string, sent *bool) (err error) {
	defer func() {
		if err != nil && !*sent {
			err = markNotSent(err)
		}
	}()
	return adapter.promote(ctx, id, sent)
}
func (adapter *Adapter) promote(ctx context.Context, id string, sent *bool) error {
	const operation = "promote"
	if err := adapter.productionMutationPrecheck(ctx, operation, id); err != nil {
		return err
	}
	deployment, err := adapter.fetchDeployment(ctx, operation, id)
	if err != nil {
		return err
	}
	if deployment.ReadyState != readyStateReady || deployment.substate != substateStaged {
		return safeError(operation, "NOT_STAGED_READY_PRODUCTION", provider.RetryNever)
	}
	return adapter.send(ctx, apiCall{operation: operation, method: http.MethodPost,
		path: "/v10/projects" + pathSegment(adapter.scope.ProjectID) + "/promote" + pathSegment(id),
		body: []byte(`{}`), mutation: true, attempted: sent}, nil)
}

// Rollback restores production to a READY production deployment of this exact
// project that has previously served production traffic and is not currently
// live. Acceptance is asynchronous; confirm with CurrentDeployment.
func (adapter *Adapter) Rollback(ctx context.Context, id string) error {
	sent := false
	return adapter.rollbackTracked(ctx, id, &sent)
}
func (adapter *Adapter) rollbackTracked(ctx context.Context, id string, sent *bool) (err error) {
	defer func() {
		if err != nil && !*sent {
			err = markNotSent(err)
		}
	}()
	return adapter.rollback(ctx, id, sent)
}
func (adapter *Adapter) rollback(ctx context.Context, id string, sent *bool) error {
	const operation = "rollback"
	if err := adapter.productionMutationPrecheck(ctx, operation, id); err != nil {
		return err
	}
	deployment, err := adapter.fetchDeployment(ctx, operation, id)
	if err != nil {
		return err
	}
	if deployment.ReadyState != readyStateReady || deployment.substate != substatePromoted {
		return safeError(operation, "NOT_PRIOR_PRODUCTION", provider.RetryNever)
	}
	current, err := adapter.currentDeployment(ctx, operation)
	if err != nil {
		return err
	}
	if current.ID == id {
		return safeError(operation, "ALREADY_CURRENT", provider.RetryNever)
	}
	return adapter.send(ctx, apiCall{operation: operation, method: http.MethodPost,
		path: "/v9/projects" + pathSegment(adapter.scope.ProjectID) + "/rollback" + pathSegment(id),
		body: []byte(`{}`), mutation: true, attempted: sent}, nil)
}

// CurrentDeployment proves which deployment currently serves this project's
// production domains: every verified, non-redirect production domain must be
// aliased to the same READY, PROMOTED production deployment of this project,
// with no alias job in flight. It fails closed otherwise. Production scopes
// only. This is a point-in-time read; an external mutation can race it.
func (adapter *Adapter) CurrentDeployment(ctx context.Context) (Deployment, error) {
	const operation = "current_deployment"
	if adapter.scope.Environment != EnvironmentProduction {
		return Deployment{}, safeError(operation, "SCOPE_NOT_PRODUCTION", provider.RetryNever)
	}
	project, err := adapter.verifiedProject(ctx, operation)
	if err != nil {
		return Deployment{}, err
	}
	if err := aliasJobIdle(operation, project); err != nil {
		return Deployment{}, err
	}
	record, err := adapter.currentDeployment(ctx, operation)
	if err != nil {
		return Deployment{}, err
	}
	return record.Deployment, nil
}

// FindDeployment returns the single deployment of this project, created in
// the last 14 days, tagged with operationID. It refuses duplicates, tagged
// deployments outside this exact scope, and incomplete searches.
func (adapter *Adapter) FindDeployment(ctx context.Context, operationID string) (Deployment, error) {
	const operation = "find_deployment"
	if !operationIDPattern.MatchString(operationID) {
		return Deployment{}, safeError(operation, "INVALID_OPERATION_ID", provider.RetryNever)
	}
	if _, err := adapter.verifiedProject(ctx, operation); err != nil {
		return Deployment{}, err
	}
	record, err := adapter.findDeployment(ctx, operation, operationID)
	if err != nil {
		return Deployment{}, err
	}
	return record.Deployment, nil
}

// ProveDeployment rechecks a recovered build against the approved source,
// not merely the operation/scope markers. This prevents reconciliation from
// accepting a wrong-commit build after Redeploy returned a drift error.
func (adapter *Adapter) ProveDeployment(ctx context.Context, id, sourceID, operationID string) (Deployment, error) {
	if !deploymentIDPattern.MatchString(id) || !deploymentIDPattern.MatchString(sourceID) || !operationIDPattern.MatchString(operationID) {
		return Deployment{}, safeError("deployment", "INVALID_DEPLOYMENT_PROOF", provider.RetryNever)
	}
	source, e := adapter.fetchDeployment(ctx, "deployment", sourceID)
	if e != nil {
		return Deployment{}, e
	}
	created, e := adapter.fetchDeployment(ctx, "deployment", id)
	if e != nil {
		return Deployment{}, e
	}
	if created.operationID != operationID || created.scopeMarker != adapter.scope.Fingerprint() {
		return Deployment{}, safeError("deployment", "APPROVED_SOURCE_UNVERIFIED", provider.RetryNever)
	}
	if adapter.scope.Environment == EnvironmentProduction && created.ReadyState == readyStateReady && created.substate != substateStaged {
		return Deployment{}, safeError("deployment", "UNEXPECTED_PROMOTION", provider.RetryNever)
	}
	// An operation-owned production build may need emergency rollback even
	// when its commit differs. Never mistake that for permission to activate it.
	if source.Prebuilt || created.Prebuilt || source.CommitSHA == "" || created.CommitSHA != source.CommitSHA || source.GitBranch != "" && created.GitBranch != source.GitBranch || created.SourceDeploymentID != sourceID {
		return Deployment{}, safeError("deployment", "APPROVED_SOURCE_UNVERIFIED", provider.RetryNever)
	}
	return created.Deployment, nil
}

func (adapter *Adapter) productionMutationPrecheck(ctx context.Context, operation, id string) error {
	if adapter.scope.Environment != EnvironmentProduction {
		return safeError(operation, "SCOPE_NOT_PRODUCTION", provider.RetryNever)
	}
	if !deploymentIDPattern.MatchString(id) {
		return safeError(operation, "INVALID_DEPLOYMENT_ID", provider.RetryNever)
	}
	project, err := adapter.verifiedProject(ctx, operation)
	if err != nil {
		return err
	}
	return aliasJobIdle(operation, project)
}

func aliasJobIdle(operation string, project projectInfo) error {
	if project.LastAliasRequest == nil {
		return nil
	}
	switch project.LastAliasRequest.JobStatus {
	case "succeeded", "failed", "skipped":
		// Completed jobs are not trusted for state; aliases are read directly.
		return nil
	case "pending", "in-progress":
		return safeError(operation, "ALIAS_JOB_IN_PROGRESS", provider.RetrySafe)
	default:
		return safeError(operation, "ALIAS_JOB_UNKNOWN", provider.RetryNever)
	}
}

func (adapter *Adapter) currentDeployment(ctx context.Context, operation string) (deploymentRecord, error) {
	var listing struct {
		Domains *[]struct {
			Name                string  `json:"name"`
			ProjectID           string  `json:"projectId"`
			Redirect            *string `json:"redirect"`
			GitBranch           *string `json:"gitBranch"`
			CustomEnvironmentID *string `json:"customEnvironmentId"`
			Verified            *bool   `json:"verified"`
		} `json:"domains"`
		Pagination *struct {
			Next *json.Number `json:"next"`
		} `json:"pagination"`
	}
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path:  "/v9/projects" + pathSegment(adapter.scope.ProjectID) + "/domains",
		query: url.Values{"production": {"true"}, "redirects": {"false"}, "limit": {"100"}}},
		func(raw []byte) error { return json.Unmarshal(raw, &listing) })
	if err != nil {
		return deploymentRecord{}, err
	}
	if listing.Domains == nil {
		return deploymentRecord{}, safeError(operation, "DOMAIN_LIST_INVALID", provider.RetryNever)
	}
	if listing.Pagination != nil && listing.Pagination.Next != nil {
		return deploymentRecord{}, safeError(operation, "DOMAIN_LIST_INCOMPLETE", provider.RetryNever)
	}
	names := make([]string, 0, len(*listing.Domains))
	for _, domain := range *listing.Domains {
		if domain.ProjectID != adapter.scope.ProjectID {
			return deploymentRecord{}, safeError(operation, "DOMAIN_SCOPE_MISMATCH", provider.RetryNever)
		}
		// Branch, custom-environment, redirect and unverified domains do not
		// serve this project's production deployment.
		if !emptyString(domain.Redirect) || !emptyString(domain.GitBranch) ||
			!emptyString(domain.CustomEnvironmentID) || domain.Verified == nil || !*domain.Verified {
			continue
		}
		if !hostnamePattern.MatchString(domain.Name) {
			return deploymentRecord{}, safeError(operation, "DOMAIN_METADATA_INVALID", provider.RetryNever)
		}
		names = append(names, domain.Name)
	}
	if len(names) == 0 {
		return deploymentRecord{}, safeError(operation, "NO_PRODUCTION_DOMAIN", provider.RetryNever)
	}
	if len(names) > maxProductionAlias {
		return deploymentRecord{}, safeError(operation, "TOO_MANY_PRODUCTION_DOMAINS", provider.RetryNever)
	}
	currentID := ""
	for _, name := range names {
		var alias struct {
			Alias        string  `json:"alias"`
			ProjectID    *string `json:"projectId"`
			DeploymentID *string `json:"deploymentId"`
			Redirect     *string `json:"redirect"`
			Deployment   *struct {
				ID string `json:"id"`
			} `json:"deployment"`
		}
		err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
			path: "/v4/aliases" + pathSegment(name), query: url.Values{"projectId": {adapter.scope.ProjectID}}},
			func(raw []byte) error { return json.Unmarshal(raw, &alias) })
		if err != nil {
			return deploymentRecord{}, err
		}
		if !strings.EqualFold(alias.Alias, name) || alias.ProjectID == nil || *alias.ProjectID != adapter.scope.ProjectID ||
			!emptyString(alias.Redirect) || alias.DeploymentID == nil || !deploymentIDPattern.MatchString(*alias.DeploymentID) ||
			(alias.Deployment != nil && alias.Deployment.ID != *alias.DeploymentID) {
			return deploymentRecord{}, safeError(operation, "PRODUCTION_ALIAS_UNVERIFIED", provider.RetryNever)
		}
		if currentID == "" {
			currentID = *alias.DeploymentID
		} else if currentID != *alias.DeploymentID {
			return deploymentRecord{}, safeError(operation, "PRODUCTION_ALIAS_SPLIT", provider.RetryNever)
		}
	}
	record, err := adapter.fetchDeployment(ctx, operation, currentID)
	if err != nil {
		return deploymentRecord{}, err
	}
	switch {
	case record.ReadyState == readyStateReady && record.substate == substatePromoted:
		return record, nil
	case record.substate == substateRolling:
		return deploymentRecord{}, safeError(operation, "ROLLING_RELEASE_ACTIVE", provider.RetryNever)
	default:
		return deploymentRecord{}, safeError(operation, "CURRENT_DEPLOYMENT_UNVERIFIED", provider.RetryNever)
	}
}

func (adapter *Adapter) findDeployment(ctx context.Context, operation, operationID string) (deploymentRecord, error) {
	since := adapter.now().Add(-findWindow).UnixMilli()
	until := ""
	complete := false
	candidates := []string{}
	seen := map[string]struct{}{}
	for page := 0; page < findMaxPages; page++ {
		query := url.Values{"projectId": {adapter.scope.ProjectID}, "limit": {strconv.Itoa(findPageLimit)},
			"since": {strconv.FormatInt(since, 10)}}
		if until != "" {
			query.Set("until", until)
		}
		var listing struct {
			Deployments *[]struct {
				UID       string                     `json:"uid"`
				ProjectID string                     `json:"projectId"`
				Meta      map[string]json.RawMessage `json:"meta"`
			} `json:"deployments"`
			Pagination *struct {
				Next *json.Number `json:"next"`
			} `json:"pagination"`
		}
		err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet, path: "/v7/deployments",
			query: query}, func(raw []byte) error { return json.Unmarshal(raw, &listing) })
		if err != nil {
			return deploymentRecord{}, err
		}
		if listing.Deployments == nil || len(*listing.Deployments) > findPageLimit {
			return deploymentRecord{}, safeError(operation, "DEPLOYMENT_LIST_INVALID", provider.RetryNever)
		}
		for _, item := range *listing.Deployments {
			marker, _ := metaString(item.Meta, MetaOperationKey)
			if marker != operationID {
				continue
			}
			if !deploymentIDPattern.MatchString(item.UID) || item.ProjectID != adapter.scope.ProjectID {
				return deploymentRecord{}, safeError(operation, codeOperationScope, provider.RetryNever)
			}
			if _, duplicate := seen[item.UID]; !duplicate {
				seen[item.UID] = struct{}{}
				candidates = append(candidates, item.UID)
			}
		}
		if listing.Pagination == nil || listing.Pagination.Next == nil {
			complete = true
			break
		}
		next := listing.Pagination.Next.String()
		if !timestampPattern.MatchString(next) || next == until {
			return deploymentRecord{}, safeError(operation, "DEPLOYMENT_LIST_INVALID", provider.RetryNever)
		}
		until = next
	}
	if !complete {
		return deploymentRecord{}, safeError(operation, "SEARCH_INCOMPLETE", provider.RetryNever)
	}
	switch len(candidates) {
	case 0:
		return deploymentRecord{}, safeError(operation, codeNotFound, provider.RetrySafe)
	case 1:
	default:
		return deploymentRecord{}, safeError(operation, "DUPLICATE_OPERATION", provider.RetryNever)
	}
	record, err := adapter.fetchDeployment(ctx, operation, candidates[0])
	if err != nil {
		if hasCode(err, codeScopeMismatch) {
			return deploymentRecord{}, safeError(operation, codeOperationScope, provider.RetryNever)
		}
		return deploymentRecord{}, err
	}
	if record.operationID != operationID || record.scopeMarker != adapter.scope.Fingerprint() {
		return deploymentRecord{}, safeError(operation, codeOperationScope, provider.RetryNever)
	}
	return record, nil
}

func (adapter *Adapter) fetchDeployment(ctx context.Context, operation, id string) (deploymentRecord, error) {
	var wire deploymentWire
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path: "/v13/deployments" + pathSegment(id), query: url.Values{"withGitRepoInfo": {"true"}}},
		func(raw []byte) error { return json.Unmarshal(raw, &wire) })
	if err != nil {
		return deploymentRecord{}, err
	}
	return adapter.normalize(operation, wire, id)
}

// normalize validates a deployment against the exact scope and converts it to
// safe metadata. expectedID guards against forged or substituted IDs.
func (adapter *Adapter) normalize(operation string, wire deploymentWire, expectedID string) (deploymentRecord, error) {
	scope := adapter.scope
	if wire.ID != expectedID || !deploymentIDPattern.MatchString(wire.ID) {
		return deploymentRecord{}, safeError(operation, "DEPLOYMENT_ID_MISMATCH", provider.RetryNever)
	}
	if wire.ProjectID != scope.ProjectID || wire.OwnerID != scope.TeamID ||
		(wire.Team != nil && wire.Team.ID != scope.TeamID) {
		return deploymentRecord{}, safeError(operation, codeScopeMismatch, provider.RetryNever)
	}
	invalid := safeError(operation, "DEPLOYMENT_METADATA_INVALID", provider.RetryNever)
	if _, known := readyStates[wire.ReadyState]; !known || len(wire.Meta) > maxDeploymentMeta {
		return deploymentRecord{}, invalid
	}
	switch wire.ReadySubstate {
	case "", substateStaged, substatePromoted, substateRolling:
	default:
		return deploymentRecord{}, invalid
	}
	if wire.URL != "" && !hostnamePattern.MatchString(wire.URL) {
		return deploymentRecord{}, invalid
	}
	environment, customID, ok := deploymentEnvironment(wire)
	if !ok {
		return deploymentRecord{}, invalid
	}
	if environment != scope.Environment || customID != scope.CustomEnvironmentID {
		return deploymentRecord{}, safeError(operation, codeScopeMismatch, provider.RetryNever)
	}
	branch, branchOK := agreedValue(gitValue(wire.GitSource, true),
		metaValues(wire.Meta, "githubCommitRef", "gitlabCommitRef", "bitbucketCommitRef"))
	sha, shaOK := agreedValue(gitValue(wire.GitSource, false),
		metaValues(wire.Meta, "githubCommitSha", "gitlabCommitSha", "bitbucketCommitSha"))
	if !branchOK || !shaOK || (branch != "" && !validGitBranch(branch)) ||
		(sha != "" && !commitSHAPattern.MatchString(sha)) {
		return deploymentRecord{}, invalid
	}
	if scope.Environment == EnvironmentPreview && scope.GitBranch != "" && branch != scope.GitBranch {
		return deploymentRecord{}, safeError(operation, codeScopeMismatch, provider.RetryNever)
	}
	operationID, scopeMarker, markersOK := markers(wire.Meta)
	if !markersOK {
		return deploymentRecord{}, invalid
	}
	sourceID, sourceOK := metaString(wire.Meta, MetaSourceKey)
	if _, present := wire.Meta[MetaSourceKey]; present && (!sourceOK || !deploymentIDPattern.MatchString(sourceID)) {
		return deploymentRecord{}, invalid
	}
	scopeOK := scopeMarker != ""
	if scopeOK && scopeMarker != scope.Fingerprint() {
		// Created by EnvBank for a different scope (e.g. another branch).
		return deploymentRecord{}, safeError(operation, codeScopeMismatch, provider.RetryNever)
	}
	return deploymentRecord{Deployment: Deployment{ID: wire.ID, ProjectID: wire.ProjectID,
		TeamID: wire.OwnerID, Environment: environment, GitBranch: branch, URL: wire.URL,
		ReadyState: wire.ReadyState, CommitSHA: sha, SourceDeploymentID: sourceID, Prebuilt: wire.Prebuilt}, substate: wire.ReadySubstate, commitSHA: sha,
		operationID: operationID, scopeMarker: scopeMarker}, nil
}

func deploymentEnvironment(wire deploymentWire) (string, string, bool) {
	target := ""
	if wire.Target != nil {
		target = *wire.Target
	}
	if wire.CustomEnvironment != nil {
		if !customEnvIDPattern.MatchString(wire.CustomEnvironment.ID) || target == EnvironmentProduction {
			return "", "", false
		}
		return EnvironmentCustom, wire.CustomEnvironment.ID, true
	}
	switch target {
	case EnvironmentProduction:
		return EnvironmentProduction, "", true
	case "", EnvironmentPreview:
		return EnvironmentPreview, "", true
	default:
		return "", "", false
	}
}

func gitValue(source *gitSourceWire, ref bool) []string {
	if source == nil {
		return nil
	}
	if ref {
		return []string{source.Ref}
	}
	return []string{source.SHA}
}

func metaValues(meta map[string]json.RawMessage, keys ...string) []string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := metaString(meta, key); ok {
			values = append(values, value)
		} else if _, present := meta[key]; present {
			values = append(values, "\x00invalid")
		}
	}
	return values
}

// agreedValue returns the single non-empty value reported by all sources; any
// disagreement or malformed source fails closed.
func agreedValue(groups ...[]string) (string, bool) {
	agreed := ""
	for _, group := range groups {
		for _, value := range group {
			if value == "" {
				continue
			}
			if strings.ContainsRune(value, 0) || (agreed != "" && agreed != value) {
				return "", false
			}
			agreed = value
		}
	}
	return agreed, true
}

// markers extracts EnvBank's reconciliation markers. A present marker that is
// not a well-formed string fails closed.
func markers(meta map[string]json.RawMessage) (string, string, bool) {
	operationID, operationOK := metaString(meta, MetaOperationKey)
	if _, present := meta[MetaOperationKey]; present && (!operationOK || !operationIDPattern.MatchString(operationID)) {
		return "", "", false
	}
	scopeMarker, scopeOK := metaString(meta, MetaScopeKey)
	if _, present := meta[MetaScopeKey]; present && (!scopeOK || !fingerprintPattern.MatchString(scopeMarker)) {
		return "", "", false
	}
	return operationID, scopeMarker, true
}

func metaString(meta map[string]json.RawMessage, key string) (string, bool) {
	raw, present := meta[key]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func hasCode(err error, code string) bool {
	var safe provider.Error
	return errors.As(err, &safe) && safe.Code == code
}
