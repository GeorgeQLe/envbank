package provideraction

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

// Strict identifier patterns (docs/provider-actions.md). Provider-returned
// IDs are checked against the same patterns before they enter a result.
var (
	vercelTeamRe       = regexp.MustCompile(`^team_[A-Za-z0-9]{1,64}$`)
	vercelProjectRe    = regexp.MustCompile(`^prj_[A-Za-z0-9]{1,64}$`)
	vercelDeploymentRe = regexp.MustCompile(`^dpl_[A-Za-z0-9]{1,64}$`)
	vercelNameRe       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$`)
	gitRepoRe          = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	frameworkRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	gitBranchRe        = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}$`)
	neonProjectRe      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	neonBranchRe       = regexp.MustCompile(`^br-[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$`)
	neonNameRe         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	neonRegionRe       = regexp.MustCompile(`^(?:aws|azure|gcp)-[a-z0-9-]{1,40}$`)
	pgIdentRe          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	stripeEndpointRe   = regexp.MustCompile(`^we_[A-Za-z0-9]{1,64}$`)
	stripeEventRe      = regexp.MustCompile(`^(?:\*|[a-z0-9_]+(?:\.[a-z0-9_]+){1,4})$`)
	healthPathRe       = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)
	urlHostRe          = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z][a-z0-9-]{0,62}$`) // a DNS name, never an IP literal
)

// Bounds.
const (
	maxParamsBytes = 16 << 10
	maxURLBytes    = 256
	maxEvents      = 16
	maxVariables   = 16
	maxRecordName  = 64
)

// Targets.
const (
	TargetPreview    = "preview"
	TargetProduction = "production"
)

var errInvalid = errors.New(agentbroker.CodeInvalidRequest)

// decodeStrict decodes exactly one JSON object with no unknown fields.
func decodeStrict(raw json.RawMessage, v any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '{' || len(raw) > maxParamsBytes || !utf8.Valid(raw) {
		return errInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return errInvalid
	}
	return nil
}

// validRecord: a record name an action may read or write. CONTROL_* records
// are never a source or destination of an action.
func validRecord(name string) bool {
	return len(name) <= maxRecordName && agentbroker.ValidName(name) && !agentbroker.Reserved(name)
}

func validGitBranch(b string) bool {
	return gitBranchRe.MatchString(b) && !strings.Contains(b, "..") && !strings.Contains(b, "//") && !strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".lock")
}

func validHealthPath(p string) bool {
	return healthPathRe.MatchString(p) && !strings.Contains(p, "..") && !strings.Contains(p, "//")
}

// validHTTPSURL accepts only a bounded https URL with a DNS host name, no
// user info, port or fragment, made of plain URL characters (no quotes or
// spaces, so it can be shown verbatim in an approval).
func validHTTPSURL(s string) bool {
	if s == "" || len(s) > maxURLBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("\"'`<>\\{}|^", c) >= 0 {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Port() != "" || !urlHostRe.MatchString(u.Host) {
		return false
	}
	return true
}

func validEvents(events []string) bool {
	if len(events) == 0 || len(events) > maxEvents {
		return false
	}
	seen := map[string]bool{}
	for _, e := range events {
		if !stripeEventRe.MatchString(e) || seen[e] {
			return false
		}
		seen[e] = true
	}
	return true
}

// VercelRef is a Vercel destination plus the deployment to redeploy from.
type VercelRef struct {
	TeamID    string `json:"team_id"`
	ProjectID string `json:"project_id"`
	Target    string `json:"target"`
	// Production must be true exactly when Target is production: a
	// production destination is never implied.
	Production bool   `json:"production,omitempty"`
	GitBranch  string `json:"git_branch,omitempty"`
	Deployment string `json:"deployment,omitempty"`
}

func (v VercelRef) valid(withDeployment bool) bool {
	if !vercelTeamRe.MatchString(v.TeamID) || !vercelProjectRe.MatchString(v.ProjectID) {
		return false
	}
	switch v.Target {
	case TargetPreview:
		if v.Production || (v.GitBranch != "" && !validGitBranch(v.GitBranch)) {
			return false
		}
	case TargetProduction:
		if !v.Production || v.GitBranch != "" {
			return false
		}
	default:
		return false
	}
	if v.Deployment != "" && (!withDeployment || !vercelDeploymentRe.MatchString(v.Deployment)) {
		return false
	}
	return true
}

func (v VercelRef) env() VercelEnv {
	return VercelEnv{TeamID: v.TeamID, ProjectID: v.ProjectID, Target: v.Target, GitBranch: v.GitBranch}
}

// text describes the destination; a production target says PRODUCTION.
func (v VercelRef) text() string {
	t := "preview"
	if v.GitBranch != "" {
		t += " (git branch " + v.GitBranch + ")"
	}
	if v.Target == TargetProduction {
		t = "PRODUCTION"
	}
	return "Vercel " + v.ProjectID + " (" + v.TeamID + ") " + t
}

// RecordPair names the pooled and direct connection-URI records.
type RecordPair struct {
	Pooled string `json:"pooled"`
	Direct string `json:"direct"`
}

func (r RecordPair) valid() bool {
	return validRecord(r.Pooled) && validRecord(r.Direct) && r.Pooled != r.Direct
}

// Params of each action (all non-secret).
type (
	neonProjectCreate struct {
		Name      string     `json:"name"`
		RegionID  string     `json:"region_id,omitempty"`
		PGVersion int        `json:"pg_version,omitempty"`
		Roles     []string   `json:"roles,omitempty"` // default ["app_a","app_b"]; roles[0] starts active
		Records   RecordPair `json:"records"`
	}
	neonRolesPrepare struct {
		ProjectID string   `json:"project_id"`
		BranchID  string   `json:"branch_id"`
		Database  string   `json:"database"`
		OwnerRole string   `json:"owner_role"`
		Roles     []string `json:"roles,omitempty"` // default ["app_a","app_b"]
		Adopt     bool     `json:"adopt"`
	}
	neonProjectDelete struct {
		ProjectID string `json:"project_id"`
	}
	neonRotate struct {
		ProjectID  string     `json:"project_id"`
		BranchID   string     `json:"branch_id"`
		Roles      []string   `json:"roles"` // [currently active, to become active]
		OwnerRole  string     `json:"owner_role"`
		Database   string     `json:"database"`
		Records    RecordPair `json:"records"`
		Vercel     VercelRef  `json:"vercel"`
		HealthPath string     `json:"health_path"`
	}
	vercelProjectCreate struct {
		TeamID    string `json:"team_id"`
		Name      string `json:"name"`
		GitRepo   string `json:"git_repo,omitempty"`
		Framework string `json:"framework,omitempty"`
	}
	vercelProjectDelete struct {
		TeamID    string `json:"team_id"`
		ProjectID string `json:"project_id"`
	}
	vercelEnvPush struct {
		TeamID     string            `json:"team_id"`
		ProjectID  string            `json:"project_id"`
		Target     string            `json:"target"`
		Production bool              `json:"production,omitempty"`
		GitBranch  string            `json:"git_branch,omitempty"`
		Variables  map[string]string `json:"variables"` // ENV_NAME: record
	}
	vercelRedeploy struct {
		TeamID     string `json:"team_id"`
		ProjectID  string `json:"project_id"`
		Target     string `json:"target"`
		Production bool   `json:"production,omitempty"`
		Deployment string `json:"deployment,omitempty"`
		HealthPath string `json:"health_path,omitempty"`
	}
	stripeWebhookCreate struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Record string   `json:"record"`
	}
	stripeWebhookRotate struct {
		EndpointID     string    `json:"endpoint_id"`
		Record         string    `json:"record"`
		PreviousRecord string    `json:"previous_record"`
		Vercel         VercelRef `json:"vercel"`
		HealthPath     string    `json:"health_path"`
	}
	stripeWebhookDelete struct {
		EndpointID string `json:"endpoint_id"`
	}
)

// rotationRoles validates a roles param: absent means DefaultNeonRoles;
// otherwise two distinct identifiers, neither the group role nor owner.
func rotationRoles(roles []string, owner string) ([2]string, bool) {
	var out [2]string
	switch len(roles) {
	case 0:
		out = DefaultNeonRoles
	case 2:
		out = [2]string{roles[0], roles[1]}
	default:
		return out, false
	}
	for _, r := range out {
		if !pgIdentRe.MatchString(r) || strings.EqualFold(r, NeonGroupRole) || (owner != "" && strings.EqualFold(r, owner)) {
			return out, false
		}
	}
	return out, !strings.EqualFold(out[0], out[1])
}

func (p *neonProjectCreate) validate() bool {
	_, ok := rotationRoles(p.Roles, "")
	return ok && neonNameRe.MatchString(p.Name) && (p.RegionID == "" || neonRegionRe.MatchString(p.RegionID)) &&
		(p.PGVersion == 0 || (p.PGVersion >= 14 && p.PGVersion <= 18)) && p.Records.valid()
}

func (p *neonRolesPrepare) validate() bool {
	_, ok := rotationRoles(p.Roles, p.OwnerRole)
	return ok && neonProjectRe.MatchString(p.ProjectID) && neonBranchRe.MatchString(p.BranchID) &&
		pgIdentRe.MatchString(p.Database) && pgIdentRe.MatchString(p.OwnerRole) && !strings.EqualFold(p.OwnerRole, NeonGroupRole)
}

func (p *neonProjectDelete) validate() bool { return neonProjectRe.MatchString(p.ProjectID) }

func (p *neonRotate) validate() bool {
	_, ok := rotationRoles(p.Roles, p.OwnerRole)
	return ok && len(p.Roles) == 2 && neonProjectRe.MatchString(p.ProjectID) && neonBranchRe.MatchString(p.BranchID) &&
		pgIdentRe.MatchString(p.OwnerRole) && !strings.EqualFold(p.OwnerRole, NeonGroupRole) &&
		pgIdentRe.MatchString(p.Database) && p.Records.valid() && p.Vercel.valid(true) && validHealthPath(p.HealthPath)
}

func (p *vercelProjectCreate) validate() bool {
	return vercelTeamRe.MatchString(p.TeamID) && vercelNameRe.MatchString(p.Name) &&
		(p.GitRepo == "" || gitRepoRe.MatchString(p.GitRepo)) && (p.Framework == "" || frameworkRe.MatchString(p.Framework))
}

func (p *vercelProjectDelete) validate() bool {
	return vercelTeamRe.MatchString(p.TeamID) && vercelProjectRe.MatchString(p.ProjectID)
}

func (p *vercelEnvPush) ref() VercelRef {
	return VercelRef{TeamID: p.TeamID, ProjectID: p.ProjectID, Target: p.Target, Production: p.Production, GitBranch: p.GitBranch}
}

func (p *vercelEnvPush) validate() bool {
	if !p.ref().valid(false) || len(p.Variables) == 0 || len(p.Variables) > maxVariables {
		return false
	}
	for env, rec := range p.Variables {
		if !validRecord(env) || !validRecord(rec) {
			return false
		}
	}
	return true
}

// envNames returns the variable names in a fixed order.
func (p *vercelEnvPush) envNames() []string {
	names := make([]string, 0, len(p.Variables))
	for n := range p.Variables {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (p *vercelRedeploy) ref() VercelRef {
	return VercelRef{TeamID: p.TeamID, ProjectID: p.ProjectID, Target: p.Target, Production: p.Production, Deployment: p.Deployment}
}

func (p *vercelRedeploy) validate() bool {
	return p.ref().valid(true) && (p.HealthPath == "" || validHealthPath(p.HealthPath))
}

func (p *stripeWebhookCreate) validate() bool {
	return validHTTPSURL(p.URL) && validEvents(p.Events) && validRecord(p.Record)
}

func (p *stripeWebhookRotate) validate() bool {
	return stripeEndpointRe.MatchString(p.EndpointID) && validRecord(p.Record) && validRecord(p.PreviousRecord) &&
		p.Record != p.PreviousRecord && p.Vercel.valid(true) && validHealthPath(p.HealthPath)
}

func (p *stripeWebhookDelete) validate() bool { return stripeEndpointRe.MatchString(p.EndpointID) }
