// Package contract parses and validates public bundle manifests.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const (
	MaxManifestBytes = 1 << 20
	maxYAMLDepth     = 20
	maxYAMLNodes     = 10_000
	maxBundleLength  = 128
	maxPolicies      = 128
	maxRecords       = 256
	maxTargets       = 8
	maxServices      = 64
	maxVariables     = 512
	maxDependencies  = 64
	maxTemplateBytes = 16 << 10
)

var (
	bundlePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?$`)
	namePattern     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	providerPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

type Manifest struct {
	Version  int                       `yaml:"version" json:"version"`
	Bundle   string                    `yaml:"bundle" json:"bundle"`
	Policies map[string]PasswordPolicy `yaml:"policies,omitempty" json:"policies,omitempty"`
	Records  map[string]Record         `yaml:"records" json:"records"`
	Targets  map[string]Target         `yaml:"targets" json:"targets"`
}

type PasswordPolicy struct {
	Type      string `yaml:"type" json:"type"`
	Length    int    `yaml:"length" json:"length"`
	Lowercase bool   `yaml:"lowercase" json:"lowercase"`
	Uppercase bool   `yaml:"uppercase" json:"uppercase"`
	Digits    bool   `yaml:"digits" json:"digits"`
	Symbols   bool   `yaml:"symbols" json:"symbols"`
}

type Record struct {
	Source      string `yaml:"source" json:"source"`
	Policy      string `yaml:"policy,omitempty" json:"policy,omitempty"`
	Template    string `yaml:"template,omitempty" json:"template,omitempty"`
	Sensitivity string `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
}

type Target struct {
	Project       string             `yaml:"project" json:"project"`
	ProjectID     string             `yaml:"project_id,omitempty" json:"project_id,omitempty"`
	Environment   string             `yaml:"environment" json:"environment"`
	EnvironmentID string             `yaml:"environment_id,omitempty" json:"environment_id,omitempty"`
	Services      map[string]Service `yaml:"services" json:"services"`
}

type Service struct {
	ID        string              `yaml:"id,omitempty" json:"id,omitempty"`
	Order     int                 `yaml:"order" json:"order"`
	Variables map[string]Variable `yaml:"variables,omitempty" json:"variables,omitempty"`
	Absent    []string            `yaml:"absent,omitempty" json:"absent,omitempty"`
}

type Variable struct {
	Source      string `yaml:"source" json:"source"`
	Value       string `yaml:"value,omitempty" json:"value,omitempty"`
	Record      string `yaml:"record,omitempty" json:"record,omitempty"`
	Sensitivity string `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
}

type Document struct {
	Manifest  Manifest
	Canonical []byte
	Digest    string
	Derived   []string
}

// Parse rejects YAML features that can make a public contract ambiguous, then
// decodes only known fields and validates the manifest semantics.
func Parse(data []byte) (*Document, error) {
	if len(data) == 0 {
		return nil, errors.New("manifest is empty")
	}
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes)
	}
	if err := inspectYAML(data); err != nil {
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, sanitizeDecodeError(err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("manifest must contain exactly one YAML document")
		}
		return nil, sanitizeDecodeError(err)
	}

	derived, err := validate(&manifest)
	if err != nil {
		return nil, errors.New(terminalSafe(err.Error()))
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("manifest could not be canonicalized")
	}
	sum := sha256.Sum256(canonical)
	return &Document{
		Manifest: manifest, Canonical: canonical,
		Digest: hex.EncodeToString(sum[:]), Derived: derived,
	}, nil
}

func inspectYAML(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return sanitizeDecodeError(err)
	}
	if len(root.Content) != 1 {
		return errors.New("manifest must contain exactly one YAML document")
	}
	count := 0
	if err := inspectNode(root.Content[0], 1, &count); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("manifest must contain exactly one YAML document")
	}
	return nil
}

func inspectNode(node *yaml.Node, depth int, count *int) error {
	*count = *count + 1
	if *count > maxYAMLNodes {
		return fmt.Errorf("manifest exceeds %d YAML nodes", maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("manifest exceeds YAML depth %d", maxYAMLDepth)
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return locationError(node, "YAML aliases and anchors are not allowed")
	}
	if !allowedTag(node.Tag) {
		return locationError(node, "custom YAML tags are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return locationError(key, "mapping keys must be plain strings")
			}
			if key.Value == "<<" || key.Tag == "!!merge" {
				return locationError(key, "YAML merge keys are not allowed")
			}
			if _, ok := seen[key.Value]; ok {
				return locationError(key, fmt.Sprintf("duplicate field %q", key.Value))
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspectNode(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func allowedTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool", "!!null", "!!float":
		return true
	default:
		return false
	}
}

func sanitizeDecodeError(err error) error {
	message := terminalSafe(err.Error())
	if index := strings.Index(message, " cannot unmarshal"); index >= 0 {
		message = message[:index] + " has an invalid type"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return fmt.Errorf("invalid manifest: %s", message)
}

func locationError(node *yaml.Node, message string) error {
	return fmt.Errorf("invalid manifest at line %d, column %d: %s", node.Line, node.Column, message)
}

func validate(manifest *Manifest) ([]string, error) {
	if manifest.Version != 1 {
		return nil, errors.New("version: only manifest version 1 is supported")
	}
	if len(manifest.Bundle) == 0 || len(manifest.Bundle) > maxBundleLength || !bundlePattern.MatchString(manifest.Bundle) || strings.Contains(manifest.Bundle, "//") {
		return nil, fmt.Errorf("bundle: must be a valid identifier of at most %d characters", maxBundleLength)
	}
	if len(manifest.Records) == 0 || len(manifest.Records) > maxRecords {
		return nil, fmt.Errorf("records: must contain between 1 and %d entries", maxRecords)
	}
	if len(manifest.Targets) == 0 || len(manifest.Targets) > maxTargets {
		return nil, fmt.Errorf("targets: must contain between 1 and %d entries", maxTargets)
	}
	if len(manifest.Policies) > maxPolicies {
		return nil, fmt.Errorf("policies: exceeds %d entries", maxPolicies)
	}
	for _, name := range sortedMapKeys(manifest.Policies) {
		policy := manifest.Policies[name]
		if name == "" || policy.Type != "password" || policy.Length < 16 || policy.Length > 256 {
			return nil, fmt.Errorf("policies.%s: invalid password policy", name)
		}
		if !policy.Lowercase && !policy.Uppercase && !policy.Digits && !policy.Symbols {
			return nil, fmt.Errorf("policies.%s: at least one character class is required", name)
		}
	}

	dependencies := make(map[string][]string, len(manifest.Records))
	for _, name := range sortedMapKeys(manifest.Records) {
		record := manifest.Records[name]
		path := "records." + name
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: invalid environment variable name", path)
		}
		switch record.Source {
		case "generate":
			if record.Policy == "" || record.Template != "" || record.Sensitivity != "" {
				return nil, fmt.Errorf("%s: generate requires only policy", path)
			}
			if _, ok := manifest.Policies[record.Policy]; !ok {
				return nil, fmt.Errorf("%s.policy: policy does not exist", path)
			}
		case "derive":
			if record.Template == "" || record.Policy != "" || record.Sensitivity != "" {
				return nil, fmt.Errorf("%s: derive requires only template", path)
			}
			if len(record.Template) > maxTemplateBytes {
				return nil, fmt.Errorf("%s.template: exceeds %d bytes", path, maxTemplateBytes)
			}
			parsed, err := ParseTemplate(record.Template)
			if err != nil {
				return nil, fmt.Errorf("%s.template: %w", path, err)
			}
			refs := parsed.References
			if len(refs) > maxDependencies {
				return nil, fmt.Errorf("%s.template: exceeds %d dependencies", path, maxDependencies)
			}
			dependencies[name] = refs
		case "import":
			if record.Policy != "" || record.Template != "" || (record.Sensitivity != "secret" && record.Sensitivity != "public") {
				return nil, fmt.Errorf("%s: import requires sensitivity public or secret", path)
			}
		default:
			return nil, fmt.Errorf("%s.source: must be generate, derive, or import", path)
		}
	}
	for _, name := range sortedMapKeys(dependencies) {
		refs := dependencies[name]
		for _, ref := range refs {
			if _, ok := manifest.Records[ref]; !ok {
				return nil, fmt.Errorf("records.%s.template: record %s does not exist", name, ref)
			}
		}
	}
	derived, err := topologicalDerivations(dependencies)
	if err != nil {
		return nil, err
	}

	variableCount := 0
	for _, provider := range sortedMapKeys(manifest.Targets) {
		target := manifest.Targets[provider]
		path := "targets." + provider
		if !providerPattern.MatchString(provider) || target.Project == "" || target.Environment == "" {
			return nil, fmt.Errorf("%s: provider, project, and environment names are required", path)
		}
		if len(target.Services) == 0 || len(target.Services) > maxServices {
			return nil, fmt.Errorf("%s.services: must contain between 1 and %d entries", path, maxServices)
		}
		orders := make(map[int]string, len(target.Services))
		for _, serviceName := range sortedMapKeys(target.Services) {
			service := target.Services[serviceName]
			servicePath := path + ".services." + serviceName
			if serviceName == "" || service.Order < 1 {
				return nil, fmt.Errorf("%s: name and positive order are required", servicePath)
			}
			if previous, ok := orders[service.Order]; ok {
				return nil, fmt.Errorf("%s.order: duplicates service %s", servicePath, previous)
			}
			orders[service.Order] = serviceName
			variableCount += len(service.Variables)
			if variableCount > maxVariables {
				return nil, fmt.Errorf("targets: exceeds %d variables", maxVariables)
			}
			absent := make(map[string]struct{}, len(service.Absent))
			for _, name := range service.Absent {
				if !namePattern.MatchString(name) {
					return nil, fmt.Errorf("%s.absent: invalid environment variable name", servicePath)
				}
				if _, exists := absent[name]; exists {
					return nil, fmt.Errorf("%s.absent: duplicate name %s", servicePath, name)
				}
				if _, exists := service.Variables[name]; exists {
					return nil, fmt.Errorf("%s: %s cannot be both present and absent", servicePath, name)
				}
				absent[name] = struct{}{}
			}
			for _, name := range sortedMapKeys(service.Variables) {
				variable := service.Variables[name]
				if !namePattern.MatchString(name) {
					return nil, fmt.Errorf("%s.variables.%s: invalid environment variable name", servicePath, name)
				}
				if err := validateVariable(name, variable, manifest.Records); err != nil {
					return nil, fmt.Errorf("%s.variables.%s: %w", servicePath, name, err)
				}
			}
		}
	}
	return derived, nil
}

func validateVariable(name string, variable Variable, records map[string]Record) error {
	switch variable.Source {
	case "constant":
		if variable.Record != "" || variable.Sensitivity != "" {
			return errors.New("constant requires only value")
		}
		if suspiciousSecretName(name) || containsURLCredentials(variable.Value) {
			return errors.New("secret-shaped names and credential-bearing URLs cannot use public constants")
		}
	case "import":
		if variable.Value != "" || variable.Record != "" || variable.Sensitivity != "public" {
			return errors.New("destination import requires sensitivity public")
		}
	case "record":
		if variable.Value != "" || variable.Sensitivity != "" || variable.Record == "" {
			return errors.New("record source requires only record")
		}
		if _, ok := records[variable.Record]; !ok {
			return fmt.Errorf("record %s does not exist", variable.Record)
		}
	default:
		return errors.New("source must be constant, import, or record")
	}
	return nil
}

func suspiciousSecretName(name string) bool {
	parts := strings.Split(name, "_")
	var database, connection bool
	for _, part := range parts {
		switch part {
		case "SECRET", "PASSWORD", "TOKEN", "PRIVATE", "CREDENTIAL":
			return true
		case "DATABASE", "DB":
			database = true
		case "URL", "URI", "DSN":
			connection = true
		}
	}
	return database && connection ||
		strings.HasSuffix(name, "_KEY") && !strings.Contains(name, "PUBLISHABLE") && !strings.Contains(name, "PUBLIC")
}

func containsURLCredentials(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.User != nil
}

func terminalSafe(value string) string {
	var safe strings.Builder
	for _, current := range value {
		if unicode.IsPrint(current) {
			safe.WriteRune(current)
			continue
		}
		if current <= 0xffff {
			fmt.Fprintf(&safe, `\u%04x`, current)
		} else {
			fmt.Fprintf(&safe, `\U%08x`, current)
		}
	}
	return safe.String()
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topologicalDerivations(dependencies map[string][]string) ([]string, error) {
	const (
		unseen = iota
		visiting
		visited
	)
	state := make(map[string]int, len(dependencies))
	result := make([]string, 0, len(dependencies))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("records.%s.template: derivation cycle detected", name)
		case visited:
			return nil
		}
		state[name] = visiting
		refs := append([]string(nil), dependencies[name]...)
		sort.Strings(refs)
		for _, ref := range refs {
			if _, derived := dependencies[ref]; derived {
				if err := visit(ref); err != nil {
					return err
				}
			}
		}
		state[name] = visited
		result = append(result, name)
		return nil
	}
	names := make([]string, 0, len(dependencies))
	for name := range dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}
