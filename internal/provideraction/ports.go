// Package provideraction runs owner-approved provider actions for authorized
// agents (docs/provider-actions.md, envbank.provider-actions/v1).
//
// The broker, not the agent, calls the providers, with control credentials
// read from reserved CONTROL_* vault records inside a callback and wiped
// when the action ends. New secrets flow from a provider response into the
// vault (lifecycle.SecretSink) and from the vault into Vercel sensitive env
// vars (lifecycle.SecretSource). No value appears in a plan, approval text,
// status, result or error: failures are fixed step and code strings.
//
// The concrete provider clients live elsewhere; this package talks to them
// only through the small ports below, so it is tested against fakes.
package provideraction

import (
	"context"
	"errors"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// Control-credential records (reserved CONTROL_* names).
const (
	ControlVercel = "CONTROL_VERCEL_TOKEN"
	ControlNeon   = "CONTROL_NEON_API_KEY"
	ControlStripe = "CONTROL_STRIPE_KEY"
)

// NeonProjectSpec describes a project to create. All fields are validated.
type NeonProjectSpec struct {
	Name      string
	RegionID  string // empty: the provider default
	PGVersion int    // 0: the provider default
}

// NeonProject identifies a created project (no values).
type NeonProject struct {
	ProjectID string
	BranchID  string
	Role      string
	Database  string
}

// NeonPort is the Neon control-plane surface the actions need.
type NeonPort interface {
	// CreateProject creates a project and stores its pooled and direct
	// connection URIs through the sinks before returning.
	CreateProject(ctx context.Context, spec NeonProjectSpec, pooled, direct *lifecycle.SecretSink) (NeonProject, error)
	DeleteProject(ctx context.Context, projectID string) error
	// EnsureRole creates role on the branch if it does not exist yet (any
	// password it is created with is discarded, never returned).
	EnsureRole(ctx context.Context, projectID, branchID, role string) error
	// ResetRolePassword resets role's password, invalidating the old one,
	// and stores the pooled and direct URIs for database through the sinks.
	// Both sinks nil means invalidate only: the new password is discarded.
	ResetRolePassword(ctx context.Context, projectID, branchID, role, database string, pooled, direct *lifecycle.SecretSink) error
}

// VercelEnv is the destination of a sensitive env var.
type VercelEnv struct {
	TeamID    string
	ProjectID string
	Target    string // preview or production
	GitBranch string // preview only; empty for all preview branches
}

// VercelPort is the Vercel API surface the actions need.
type VercelPort interface {
	CreateProject(ctx context.Context, teamID, name, gitRepo, framework string) (projectID string, err error)
	DeleteProject(ctx context.Context, teamID, projectID string) error
	// UpsertSensitiveEnv creates or replaces key as a sensitive env var,
	// reading the value only inside value.WithSecret.
	UpsertSensitiveEnv(ctx context.Context, env VercelEnv, key string, value *lifecycle.SecretSource) error
	CurrentDeployment(ctx context.Context, teamID, projectID, target string) (deploymentID string, err error)
	Redeploy(ctx context.Context, teamID, projectID, target, sourceDeploymentID string) (deploymentID string, err error)
	// WaitReady waits until the deployment is ready and returns its HTTPS
	// base URL.
	WaitReady(ctx context.Context, teamID, deploymentID string) (deploymentURL string, err error)
	// CheckHealth makes one health request to deploymentURL+path and
	// returns nil only for a healthy (2xx) answer.
	CheckHealth(ctx context.Context, deploymentURL, path string) error
}

// StripeWebhook is an endpoint's non-secret configuration.
type StripeWebhook struct {
	URL    string
	Events []string
}

// StripePort is the Stripe API surface the actions need (test mode only).
type StripePort interface {
	// CreateWebhook creates an endpoint and stores its whsec_ signing secret
	// through secret before returning.
	CreateWebhook(ctx context.Context, url string, events []string, secret *lifecycle.SecretSink) (endpointID string, err error)
	Webhook(ctx context.Context, endpointID string) (StripeWebhook, error)
	DeleteWebhook(ctx context.Context, endpointID string) error
}

// Factory builds ports from control-credential bytes. The broker reads the
// CONTROL_* record inside a vault callback into a buffer it owns, calls the
// factory, runs one action, then zeroes the buffer. A factory and its port
// may use credential only for that action: they must read it from the slice
// per request and never copy it into longer-lived storage. A nil Factory
// (the default build) makes every provider_action PROVIDER_UNAVAILABLE.
type Factory interface {
	Neon(credential []byte) (NeonPort, error)
	Vercel(credential []byte) (VercelPort, error)
	Stripe(credential []byte) (StripePort, error)
}

// Vault is the owner-unlocked store as the actions see it: revisioned,
// callback-scoped reads and durable writes. Implementations never log values.
type Vault interface {
	// StoreSecret durably encrypts the value fill supplies under name and
	// returns its new revision (lifecycle.RecordWriter).
	lifecycle.RecordWriter
	// ReadSecret calls consume with exactly revision of name, or fails
	// (lifecycle.RecordReader).
	lifecycle.RecordReader
	// Latest calls consume with the current value of name and returns its
	// revision; ErrMissing if absent.
	Latest(ctx context.Context, name string, consume func([]byte) error) (int64, error)
	Exists(ctx context.Context, name string) (bool, error)
}

// ErrMissing is returned by Vault.Latest for an absent record.
var ErrMissing = errors.New("record not found")
