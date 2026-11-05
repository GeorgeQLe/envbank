package vercel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

// LatestPreviewDeployment returns the newest READY preview deployment of this
// exact preview scope (and branch, for a branch-scoped preview), freshly
// proven with the same ownership and scope checks as Deployment. Preview has
// no single "current" deployment the way production has its aliases; this is
// the one a redeploy-from-current should rebuild. Preview scopes only; it is a
// point-in-time read.
func (adapter *Adapter) LatestPreviewDeployment(ctx context.Context) (Deployment, error) {
	const operation = "current_deployment"
	if adapter == nil {
		return Deployment{}, safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if adapter.scope.Environment != EnvironmentPreview {
		return Deployment{}, safeError(operation, "SCOPE_NOT_PREVIEW", provider.RetryNever)
	}
	query := url.Values{"projectId": {adapter.scope.ProjectID}, "target": {EnvironmentPreview},
		"state": {readyStateReady}, "limit": {"1"}}
	if adapter.scope.GitBranch != "" {
		query.Set("branch", adapter.scope.GitBranch)
	}
	var listing struct {
		Deployments *[]struct {
			UID       string `json:"uid"`
			ProjectID string `json:"projectId"`
		} `json:"deployments"`
	}
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet, path: "/v6/deployments",
		query: query}, func(raw []byte) error { return json.Unmarshal(raw, &listing) })
	if err != nil {
		return Deployment{}, err
	}
	if listing.Deployments == nil || len(*listing.Deployments) > 1 {
		return Deployment{}, safeError(operation, "DEPLOYMENT_LIST_INVALID", provider.RetryNever)
	}
	if len(*listing.Deployments) == 0 {
		return Deployment{}, safeError(operation, codeNotFound, provider.RetryNever)
	}
	item := (*listing.Deployments)[0]
	if !deploymentIDPattern.MatchString(item.UID) || item.ProjectID != adapter.scope.ProjectID {
		return Deployment{}, safeError(operation, codeScopeMismatch, provider.RetryNever)
	}
	record, err := adapter.fetchDeployment(ctx, operation, item.UID)
	if err != nil {
		return Deployment{}, err
	}
	if record.ReadyState != readyStateReady {
		return Deployment{}, safeError(operation, "CURRENT_DEPLOYMENT_UNVERIFIED", provider.RetryNever)
	}
	return record.Deployment, nil
}
