// Package vercel implements EnvBank's Vercel adapter. It writes project
// environment variables only as write-only "sensitive" variables in one exact
// team/project/environment(/branch) scope, inspects names-only metadata, and
// exposes narrowly validated deployment operations.
//
// Limitations that callers must account for:
//
//   - Vercel offers no compare-and-swap for environment variables, deployments
//     or production aliases. Every pre-mutation check here is a fresh read, but
//     an external dashboard/API mutation can race between that read and the
//     mutation. Callers must re-check after mutations.
//   - Verification is metadata-only. Sensitive values cannot be read back, so
//     Verify never reports more than VerificationLimited presence.
//   - API acceptance (including READY deployment state) does not prove
//     application health.
package vercel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	ProviderName = "vercel"
	// ServiceName is the only service key in a Vercel provider.Target.
	ServiceName = "environment"

	EnvironmentPreview    = "preview"
	EnvironmentProduction = "production"
	EnvironmentCustom     = "custom"

	scopeFingerprintVersion = "envbank.vercel.scope.v1"
	maxGitBranchBytes       = 250
)

var (
	teamIDPattern        = regexp.MustCompile(`^team_[A-Za-z0-9]{1,64}$`)
	projectIDPattern     = regexp.MustCompile(`^prj_[A-Za-z0-9]{1,64}$`)
	customEnvIDPattern   = regexp.MustCompile(`^env_[A-Za-z0-9]{1,64}$`)
	deploymentIDPattern  = regexp.MustCompile(`^dpl_[A-Za-z0-9]{1,64}$`)
	envVarIDPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	envKeyPattern        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)
	projectNamePattern   = regexp.MustCompile(`^[a-z0-9._-]{1,100}$`)
	operationIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$`)
	hostnamePattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	commitSHAPattern     = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	fingerprintPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitBranchForbiddenRE = regexp.MustCompile(`\.\.|@\{|//|\.lock$|/\.|^\.|\.$|/$|^/|^-`)
)

// Scope is one exact, non-secret Vercel variable/deployment scope.
//
// Environment is "preview", "production" or "custom". Development is rejected
// because Vercel does not allow sensitive (write-only) development variables.
// GitBranch is only valid for preview: empty means every preview branch, a
// value means that exact branch. CustomEnvironmentID is required for, and only
// valid for, custom environments; slugs are not accepted because they are
// mutable.
type Scope struct {
	TeamID              string `json:"team_id"`
	ProjectID           string `json:"project_id"`
	Environment         string `json:"environment"`
	GitBranch           string `json:"git_branch,omitempty"`
	CustomEnvironmentID string `json:"custom_environment_id,omitempty"`
}

// Validate never echoes scope values in its errors.
func (scope Scope) Validate() error {
	if !teamIDPattern.MatchString(scope.TeamID) {
		return errors.New("Vercel scope team ID is invalid")
	}
	if !projectIDPattern.MatchString(scope.ProjectID) {
		return errors.New("Vercel scope project ID is invalid")
	}
	switch scope.Environment {
	case EnvironmentProduction:
		if scope.GitBranch != "" || scope.CustomEnvironmentID != "" {
			return errors.New("Vercel production scope cannot have a branch or custom environment")
		}
	case EnvironmentPreview:
		if scope.CustomEnvironmentID != "" {
			return errors.New("Vercel preview scope cannot have a custom environment")
		}
		if scope.GitBranch != "" && !validGitBranch(scope.GitBranch) {
			return errors.New("Vercel scope git branch is invalid")
		}
	case EnvironmentCustom:
		if scope.GitBranch != "" {
			return errors.New("Vercel custom scope cannot have a branch")
		}
		if !customEnvIDPattern.MatchString(scope.CustomEnvironmentID) {
			return errors.New("Vercel custom environment ID is invalid")
		}
	case "development":
		return errors.New("Vercel development scope is unsupported because it cannot hold sensitive variables")
	default:
		return errors.New("Vercel scope environment is invalid")
	}
	return nil
}

// Target binds the full scope into the generic rollout target. The service
// fingerprint covers team and branch, which the generic target has no field
// for, so immutable rollout plans cannot silently move across them.
func (scope Scope) Target() provider.Target {
	environmentID := scope.Environment
	if scope.Environment == EnvironmentCustom {
		environmentID = scope.CustomEnvironmentID
	}
	return provider.Target{ProjectID: scope.ProjectID, EnvironmentID: environmentID,
		ServiceIDs: map[string]string{ServiceName: scope.Fingerprint()}}
}

// Fingerprint is the lowercase hex SHA-256 of a versioned canonical JSON
// encoding of the non-secret scope. It never includes credentials.
func (scope Scope) Fingerprint() string {
	canonical, err := json.Marshal(struct {
		Version             string `json:"v"`
		Provider            string `json:"provider"`
		TeamID              string `json:"team_id"`
		ProjectID           string `json:"project_id"`
		Environment         string `json:"environment"`
		GitBranch           string `json:"git_branch"`
		CustomEnvironmentID string `json:"custom_environment_id"`
	}{scopeFingerprintVersion, ProviderName, scope.TeamID, scope.ProjectID, scope.Environment,
		scope.GitBranch, scope.CustomEnvironmentID})
	if err != nil {
		// Marshalling plain strings cannot fail; never return a usable value if it does.
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func (scope Scope) matchesTarget(target provider.Target) bool {
	expected := scope.Target()
	return expected.ServiceIDs[ServiceName] != "" && target.ProjectID == expected.ProjectID &&
		target.EnvironmentID == expected.EnvironmentID && len(target.ServiceIDs) == 1 &&
		target.ServiceIDs[ServiceName] == expected.ServiceIDs[ServiceName]
}

// validGitBranch is intentionally stricter than git: printable ASCII only,
// without git-forbidden characters and sequences.
func validGitBranch(branch string) bool {
	if branch == "" || len(branch) > maxGitBranchBytes || gitBranchForbiddenRE.MatchString(branch) {
		return false
	}
	for index := 0; index < len(branch); index++ {
		character := branch[index]
		if character <= ' ' || character >= 0x7f || strings.IndexByte("~^:?*[\\", character) >= 0 {
			return false
		}
	}
	return true
}

// clientExposedPrefixes are framework conventions that inline variables into
// browser bundles. Vault secrets must never be written under them.
var clientExposedPrefixes = []string{
	"NEXT_PUBLIC_", "PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "NUXT_ENV_",
	"GATSBY_", "EXPO_PUBLIC_", "VUE_APP_", "STORYBOOK_", "SANITY_STUDIO_",
	"REDWOOD_ENV_", "NG_APP_", "ASTRO_PUBLIC_", "SNOWPACK_PUBLIC_", "PLASMO_PUBLIC_",
	"VERCEL_", "NOW_", "AWS_LAMBDA_", "LAMBDA_",
}

// reservedNames are runtime names Vercel reserves or that would alter the
// runtime rather than configure the application.
var reservedNames = map[string]struct{}{
	"AWS_ACCESS_KEY_ID": {}, "AWS_SECRET_ACCESS_KEY": {}, "AWS_SESSION_TOKEN": {},
	"AWS_REGION": {}, "AWS_DEFAULT_REGION": {}, "AWS_EXECUTION_ENV": {}, "TZ": {}, "LANG": {},
	"PATH": {}, "LD_LIBRARY_PATH": {}, "NODE_OPTIONS": {}, "_HANDLER": {}, "CI": {},
}

// validSecretName reports whether a vault secret may be written under name.
func validSecretName(name string) bool {
	if !envKeyPattern.MatchString(name) {
		return false
	}
	upper := strings.ToUpper(name)
	if _, reserved := reservedNames[upper]; reserved {
		return false
	}
	for _, prefix := range clientExposedPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return false
		}
	}
	return true
}
