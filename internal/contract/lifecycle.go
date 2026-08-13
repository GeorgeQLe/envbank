package contract

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var lifecycleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// capabilityMode is deliberately conservative. A provider feature is never
// promoted to unattended operation merely because a dashboard can perform it.
var capabilityMode = map[string]map[string]string{
	"stripe": {
		"webhook-signing-secret": "automatic",
		"secret-key":             "interactive",
		"restricted-key":         "interactive",
	},
	"clerk": {
		"application-key":        "interactive",
		"webhook-signing-secret": "interactive",
	},
}

var capabilityOperations = map[string]map[string][2]string{
	"stripe": {"webhook-signing-secret": {"webhook-delivery", "delete-endpoint"}, "secret-key": {"identity", "revoke-key"}, "restricted-key": {"identity", "revoke-key"}},
	"clerk":  {"application-key": {"identity", "revoke-key"}, "webhook-signing-secret": {"webhook-delivery", "delete-endpoint"}},
}

var deploymentProviders = map[string]bool{"vercel": true, "railway": true}

func validateLifecycle(manifest *Manifest) error {
	if manifest.Environment != "sandbox" && manifest.Environment != "staging" && manifest.Environment != "production" {
		return errors.New("environment: version 2 requires sandbox, staging, or production")
	}
	if len(manifest.Credentials) == 0 || len(manifest.Credentials) > maxCredentials {
		return fmt.Errorf("credentials: must contain between 1 and %d entries", maxCredentials)
	}
	for _, name := range sortedMapKeys(manifest.Credentials) {
		credential := manifest.Credentials[name]
		path := "credentials." + name
		if !lifecycleNamePattern.MatchString(name) {
			return fmt.Errorf("%s: invalid credential name", path)
		}
		modes, known := capabilityMode[credential.Provider]
		mode, supported := modes[credential.Type]
		if !known || !supported {
			return fmt.Errorf("%s: unknown provider credential capability", path)
		}
		if credential.Mode != mode {
			return fmt.Errorf("%s.mode: capability requires %s", path, mode)
		}
		if _, ok := manifest.Records[credential.Record]; !ok {
			return fmt.Errorf("%s.record: destination record does not exist", path)
		}
		operations := capabilityOperations[credential.Provider][credential.Type]
		if credential.Validation != operations[0] || credential.Revoke != operations[1] {
			return fmt.Errorf("%s: validation or revoke operation is not a known capability", path)
		}
		if err := validateActions(path+".actions", credential.Actions); err != nil {
			return err
		}
	}

	seenTargets := map[string]bool{}
	for name, target := range manifest.Targets {
		provider := target.Provider
		if provider == "" {
			provider = name
		}
		if !deploymentProviders[provider] {
			return fmt.Errorf("targets.%s: unknown deployment provider", name)
		}
		if target.ProjectID == "" || target.EnvironmentID == "" {
			return fmt.Errorf("targets.%s: immutable project_id and environment_id are required", name)
		}
		binding := provider + "\x00" + target.ProjectID + "\x00" + target.EnvironmentID
		if seenTargets[binding] {
			return fmt.Errorf("targets.%s: ambiguous duplicate deployment binding", name)
		}
		seenTargets[binding] = true
		if target.Stage == "" || target.Activation == "" || target.Rollback == "" {
			return fmt.Errorf("targets.%s: stage, activation, and rollback are required", name)
		}
		if manifest.Environment == "production" && len(target.HealthChecks) == 0 {
			return fmt.Errorf("targets.%s.health_checks: production targets require health checks", name)
		}
		for index, check := range target.HealthChecks {
			if err := validateHealthCheck(check); err != nil {
				return fmt.Errorf("targets.%s.health_checks.%d: %w", name, index, err)
			}
		}
	}

	if len(manifest.RotationPolicies) == 0 || len(manifest.RotationPolicies) > maxPolicies {
		return fmt.Errorf("rotation_policies: must contain between 1 and %d entries", maxPolicies)
	}
	for _, name := range sortedMapKeys(manifest.RotationPolicies) {
		policy := manifest.RotationPolicies[name]
		path := "rotation_policies." + name
		if !lifecycleNamePattern.MatchString(name) || policy.Schedule == "" || policy.RetryLimit < 1 || policy.RetryLimit > 3 || policy.Rollback == "" {
			return fmt.Errorf("%s: schedule, bounded retries, and rollback are required", path)
		}
		grace, err := time.ParseDuration(policy.GracePeriod)
		if err != nil || grace <= 0 {
			return fmt.Errorf("%s.grace_period: positive duration is required", path)
		}
		if manifest.Environment == "production" && grace < 24*time.Hour {
			return fmt.Errorf("%s.grace_period: production requires at least 24h", path)
		}
		if manifest.Environment != "production" && grace < 15*time.Minute {
			return fmt.Errorf("%s.grace_period: sandbox and staging require at least 15m", path)
		}
		if len(policy.Credentials) == 0 || len(policy.Targets) == 0 || len(policy.ActivationOrder) == 0 {
			return fmt.Errorf("%s: credentials, targets, and activation_order are required", path)
		}
		for _, credential := range policy.Credentials {
			declared, ok := manifest.Credentials[credential]
			if !ok {
				return fmt.Errorf("%s.credentials: unknown credential %s", path, credential)
			}
			if declared.Mode != "automatic" && contains(policy.AllowedActions, "create") {
				return fmt.Errorf("%s: automatic rotation requested for interactive credential %s", path, credential)
			}
		}
		for _, target := range policy.Targets {
			if _, ok := manifest.Targets[target]; !ok {
				return fmt.Errorf("%s.targets: unknown target %s", path, target)
			}
		}
		for _, target := range policy.ActivationOrder {
			if !contains(policy.Targets, target) {
				return fmt.Errorf("%s.activation_order: target %s is not selected", path, target)
			}
		}
		if len(policy.ActivationOrder) != len(policy.Targets) || duplicateStrings(policy.ActivationOrder) {
			return fmt.Errorf("%s.activation_order: must contain every selected target exactly once", path)
		}
		if err := validateActions(path+".allowed_actions", policy.AllowedActions); err != nil {
			return err
		}
	}
	if len(manifest.BrowserRecipes) > maxRecipes || len(manifest.Configurations) > maxRecipes {
		return errors.New("lifecycle recipes exceed the safety limit")
	}
	for index, recipe := range manifest.Configurations {
		if capabilityMode[recipe.Provider] == nil || recipe.Operation == "" || recipe.Resource == "" {
			return fmt.Errorf("configurations.%d: known provider, operation, and resource are required", index)
		}
		for name, value := range recipe.Fields {
			if suspiciousSecretName(strings.ToUpper(name)) || containsURLCredentials(value) {
				return fmt.Errorf("configurations.%d.fields: secret-bearing public configuration is forbidden", index)
			}
		}
	}
	for index, recipe := range manifest.BrowserRecipes {
		parsed, err := url.Parse(recipe.Origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			capabilityMode[recipe.Provider] == nil || !strings.HasPrefix(recipe.Route, "/") || recipe.Selector == "" || recipe.Strategy == "" || recipe.ValuePrefix == "" {
			return fmt.Errorf("browser_recipes.%d: exact HTTPS origin, route, selector, strategy, and known provider are required", index)
		}
		if _, ok := manifest.Records[recipe.Record]; !ok {
			return fmt.Errorf("browser_recipes.%d.record: destination record does not exist", index)
		}
	}
	return nil
}

func duplicateStrings(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func validateActions(path string, actions []string) error {
	if len(actions) == 0 {
		return fmt.Errorf("%s: at least one action is required", path)
	}
	seen := map[string]bool{}
	for _, action := range actions {
		if action != "create" && action != "validate" && action != "revoke" || seen[action] {
			return fmt.Errorf("%s: actions must be unique create, validate, or revoke values", path)
		}
		seen[action] = true
	}
	return nil
}

func validateHealthCheck(check HealthCheck) error {
	parsed, err := url.Parse(check.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("an HTTPS URL without credentials or fragment is required")
	}
	if check.Method != "" && check.Method != "GET" && check.Method != "HEAD" {
		return errors.New("method must be GET or HEAD")
	}
	if check.ExpectedStatus < 200 || check.ExpectedStatus > 399 || check.Successes < 3 {
		return errors.New("status must be 2xx/3xx and at least three successes are required")
	}
	minimum, err := time.ParseDuration(check.MinimumDuration)
	if err != nil || minimum < 30*time.Second {
		return errors.New("minimum_duration must be at least 30s")
	}
	timeout, err := time.ParseDuration(check.Timeout)
	if err != nil || timeout <= 0 || timeout > 10*time.Minute || timeout < minimum {
		return errors.New("timeout must cover minimum_duration and be at most 10m")
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
