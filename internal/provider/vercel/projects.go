package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	defaultPollInterval = 5 * time.Second
	// MaxWaitReady bounds WaitReady; builds that outlast it are reported as
	// DEPLOYMENT_TIMEOUT rather than polled indefinitely.
	MaxWaitReady = 45 * time.Minute
)

var (
	// gitRepoPattern is a GitHub owner/repo pair. Owners are at most 39
	// characters of letters, digits and hyphens; repos are bounded and may also
	// contain dots and underscores but never "..".
	gitRepoPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	frameworkPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidProjectName reports whether name is an acceptable new Vercel project
// name: lowercase letters, digits, '.', '_' and '-', at most 100 bytes, and
// without the "---" sequence Vercel reserves.
func ValidProjectName(name string) bool {
	return projectNamePattern.MatchString(name) && !strings.Contains(name, "---")
}

// ValidGitRepo reports whether repo is a GitHub "owner/repo" pair.
func ValidGitRepo(repo string) bool {
	return gitRepoPattern.MatchString(repo) && !strings.Contains(repo, "..")
}

type createProjectWire struct {
	Name          string            `json:"name"`
	Framework     string            `json:"framework,omitempty"`
	GitRepository *gitRepositoryReq `json:"gitRepository,omitempty"`
}

type gitRepositoryReq struct {
	Type string `json:"type"`
	Repo string `json:"repo"`
}

type createdProjectWire struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AccountID string `json:"accountId"`
}

// CreateProject creates a project in teamID (which must be this adapter's
// team) and returns its prj_ ID. gitRepo ("owner/repo") and framework are
// optional. It is a mutation: ctx must carry WithMutationAuthorization. It is
// never retried; an ambiguous failure must be reconciled by name.
func (adapter *Adapter) CreateProject(ctx context.Context, teamID, name, gitRepo, framework string) (string, error) {
	const operation = "project_create"
	if adapter == nil {
		return "", safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if !teamIDPattern.MatchString(teamID) || teamID != adapter.scope.TeamID {
		return "", safeError(operation, "TEAM_SCOPE_MISMATCH", provider.RetryNever)
	}
	if !ValidProjectName(name) || (gitRepo != "" && !ValidGitRepo(gitRepo)) ||
		(framework != "" && !frameworkPattern.MatchString(framework)) {
		return "", safeError(operation, "INVALID_PROJECT_REQUEST", provider.RetryNever)
	}
	request := createProjectWire{Name: name, Framework: framework}
	if gitRepo != "" {
		request.GitRepository = &gitRepositoryReq{Type: "github", Repo: gitRepo}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return "", safeError(operation, "REQUEST_INVALID", provider.RetryNever)
	}
	var created createdProjectWire
	err = adapter.send(ctx, apiCall{operation: operation, method: http.MethodPost, path: "/v11/projects",
		body: body, mutation: true, teamLevel: true}, func(raw []byte) error {
		return json.Unmarshal(raw, &created)
	})
	if err != nil {
		return "", err
	}
	if !projectIDPattern.MatchString(created.ID) || created.Name != name || created.AccountID != teamID {
		return "", safeError(operation, "CREATED_PROJECT_MISMATCH", provider.RetryAmbiguous)
	}
	return created.ID, nil
}

// DeleteProject deletes projectID after a fresh read proves it is owned by
// teamID (this adapter's team). On a project-scoped adapter projectID must be
// the scoped project. It is a mutation: ctx must carry
// WithMutationAuthorization. A missing project is reported as NOT_FOUND.
func (adapter *Adapter) DeleteProject(ctx context.Context, teamID, projectID string) error {
	const operation = "project_delete"
	if adapter == nil {
		return safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if !teamIDPattern.MatchString(teamID) || teamID != adapter.scope.TeamID {
		return safeError(operation, "TEAM_SCOPE_MISMATCH", provider.RetryNever)
	}
	if !projectIDPattern.MatchString(projectID) || (!adapter.teamOnly && projectID != adapter.scope.ProjectID) {
		return safeError(operation, "INVALID_PROJECT_ID", provider.RetryNever)
	}
	var project createdProjectWire
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path: "/v9/projects" + pathSegment(projectID), teamLevel: true}, func(raw []byte) error {
		return json.Unmarshal(raw, &project)
	})
	if err != nil {
		return err
	}
	if project.ID != projectID || project.AccountID != teamID {
		return safeError(operation, "PROJECT_OWNERSHIP_MISMATCH", provider.RetryNever)
	}
	return adapter.send(ctx, apiCall{operation: operation, method: http.MethodDelete,
		path: "/v9/projects" + pathSegment(projectID), mutation: true, teamLevel: true}, nil)
}

// WaitReady polls Deployment until the deployment is READY (returned), or
// ERROR, CANCELED or DELETED (a fixed-code error), or until timeout, which
// must be in (0, MaxWaitReady]. Retry-safe read failures are retried within
// the deadline; READY proves only build acceptance, not application health.
func (adapter *Adapter) WaitReady(ctx context.Context, deploymentID string, timeout time.Duration) (Deployment, error) {
	const operation = "wait_ready"
	if adapter == nil {
		return Deployment{}, safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if !deploymentIDPattern.MatchString(deploymentID) {
		return Deployment{}, safeError(operation, "INVALID_DEPLOYMENT_ID", provider.RetryNever)
	}
	if timeout <= 0 || timeout > MaxWaitReady {
		return Deployment{}, safeError(operation, "INVALID_TIMEOUT", provider.RetryNever)
	}
	interval := adapter.pollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		deployment, err := adapter.Deployment(waitCtx, deploymentID)
		if err == nil {
			switch deployment.ReadyState {
			case readyStateReady:
				return deployment, nil
			case "ERROR":
				return Deployment{}, safeError(operation, "DEPLOYMENT_FAILED", provider.RetryNever)
			case "CANCELED":
				return Deployment{}, safeError(operation, "DEPLOYMENT_CANCELED", provider.RetryNever)
			case "DELETED":
				return Deployment{}, safeError(operation, "DEPLOYMENT_DELETED", provider.RetryNever)
			}
		} else if waitCtx.Err() == nil {
			var safe provider.Error
			if !errors.As(err, &safe) || safe.Retry != provider.RetrySafe {
				return Deployment{}, err
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return Deployment{}, safeError(operation, "CANCELLED", provider.RetrySafe)
			}
			return Deployment{}, safeError(operation, "DEPLOYMENT_TIMEOUT", provider.RetrySafe)
		case <-timer.C:
		}
	}
}
