package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

// AcceptanceProjectMarker is the required provider-side name prefix of a
// disposable acceptance project.
const AcceptanceProjectMarker = "envbank-acceptance-"

var acceptanceProjectNamePattern = regexp.MustCompile(`^envbank-acceptance-[a-z0-9][a-z0-9._-]{0,80}$`)

const maxAcceptanceDomains = 100

// WithAdditionalMutationAuthorization composes an extra trusted admission check
// with the existing signed-policy authorization. Policy is checked before the
// guard and AGAIN afterwards so a slow guard cannot age out approval/health.
// It never replaces or removes that check:
// if ctx carries none, or extra is nil, every mutation stays denied.
func WithAdditionalMutationAuthorization(ctx context.Context, extra func(context.Context) error) context.Context {
	existing, _ := ctx.Value(mutationAuthorityKey{}).(func(context.Context) error)
	return context.WithValue(ctx, mutationAuthorityKey{}, func(c context.Context) error {
		if existing == nil || extra == nil {
			return errors.New("mutation authorization unavailable")
		}
		if err := existing(c); err != nil {
			return err
		}
		if err := extra(c); err != nil {
			return err
		}
		return existing(c)
	})
}

// RefusedBeforeSend is for trusted embedding wrappers that refuse a mutation
// BEFORE invoking the mutating adapter method at all. It accepts only a fixed
// code, never an error returned by a mutating call, so it cannot relabel a
// possibly-sent request as safely unsent.
func RefusedBeforeSend(operation, code string) error {
	return markNotSent(safeError(operation, code, provider.RetrySafe))
}

// VerifyDisposableProductionProject is a read-only admission guard for
// disposable Production acceptance. It freshly proves, with the adapter's
// existing token and safe-error handling, that:
//
//   - the scope is exact Production (no branch, no custom environment);
//   - the project ID and owning team match, and the provider-reported name is
//     exactly expectedName and carries the disposable acceptance marker;
//   - no alias job is in flight;
//   - the complete (unpaginated) list of ALL project domains contains exactly
//     one domain: the default PROJECT_NAME.vercel.app, verified, owned by this
//     project, Production (no git branch / custom environment) and not a
//     redirect. Any custom domain, branch or custom-environment domain,
//     redirect, unverified entry or incomplete listing is refused, so this admission
//     check rejects attached customer domains before promotion or rollback.
//
// It never sends a mutation. It is a point-in-time read: Vercel has no
// compare-and-swap, so a concurrent external dashboard/API change can still
// race it. Callers re-run it immediately before every mutation.
func (adapter *Adapter) VerifyDisposableProductionProject(ctx context.Context, expectedName string) error {
	const operation = "acceptance_guard"
	if adapter == nil {
		return safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if adapter.scope.Environment != EnvironmentProduction || adapter.scope.GitBranch != "" || adapter.scope.CustomEnvironmentID != "" {
		return safeError(operation, "SCOPE_NOT_PRODUCTION", provider.RetryNever)
	}
	if !acceptanceProjectNamePattern.MatchString(expectedName) {
		return safeError(operation, "ACCEPTANCE_PROJECT_NOT_MARKED", provider.RetryNever)
	}
	project, err := adapter.verifiedProject(ctx, operation)
	if err != nil {
		return err
	}
	if project.Name != expectedName {
		return safeError(operation, "ACCEPTANCE_PROJECT_NOT_MARKED", provider.RetryNever)
	}
	if err := aliasJobIdle(operation, project); err != nil {
		return err
	}
	var listing struct {
		Domains *[]struct {
			Name                string       `json:"name"`
			ProjectID           string       `json:"projectId"`
			Redirect            *string      `json:"redirect"`
			RedirectStatusCode  *json.Number `json:"redirectStatusCode"`
			GitBranch           *string      `json:"gitBranch"`
			CustomEnvironmentID *string      `json:"customEnvironmentId"`
			Verified            *bool        `json:"verified"`
		} `json:"domains"`
		Pagination *struct {
			Count *json.Number `json:"count"`
			Next  *json.Number `json:"next"`
		} `json:"pagination"`
	}
	// No production/redirect/branch filters: every domain of the project must
	// be visible so a custom or redirect domain cannot hide from the guard.
	err = adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path:  "/v9/projects" + pathSegment(adapter.scope.ProjectID) + "/domains",
		query: url.Values{"limit": {"100"}}},
		func(raw []byte) error { return json.Unmarshal(raw, &listing) })
	if err != nil {
		return err
	}
	if listing.Domains == nil || len(*listing.Domains) > maxAcceptanceDomains {
		return safeError(operation, "DOMAIN_LIST_INVALID", provider.RetryNever)
	}
	if listing.Pagination != nil && (listing.Pagination.Next != nil ||
		listing.Pagination.Count != nil && listing.Pagination.Count.String() != "1") {
		return safeError(operation, "DOMAIN_LIST_INCOMPLETE", provider.RetryNever)
	}
	if len(*listing.Domains) != 1 {
		return safeError(operation, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", provider.RetryNever)
	}
	domain := (*listing.Domains)[0]
	if domain.Name != expectedName+".vercel.app" || !hostnamePattern.MatchString(domain.Name) {
		return safeError(operation, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", provider.RetryNever)
	}
	if domain.ProjectID != adapter.scope.ProjectID {
		return safeError(operation, "DOMAIN_SCOPE_MISMATCH", provider.RetryNever)
	}
	if !emptyString(domain.Redirect) || domain.RedirectStatusCode != nil ||
		!emptyString(domain.GitBranch) || !emptyString(domain.CustomEnvironmentID) {
		return safeError(operation, "ACCEPTANCE_DOMAIN_NOT_DEFAULT_PRODUCTION", provider.RetryNever)
	}
	if domain.Verified == nil || !*domain.Verified {
		return safeError(operation, "ACCEPTANCE_DOMAIN_UNVERIFIED", provider.RetryNever)
	}
	return nil
}
