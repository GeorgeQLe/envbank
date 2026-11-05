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
	"io"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// Control-credential records (reserved CONTROL_* names).
const (
	ControlVercel = "CONTROL_VERCEL_TOKEN"
	ControlNeon   = "CONTROL_NEON_API_KEY"
	ControlStripe = "CONTROL_STRIPE_KEY"
)

// NeonGroupRole is the no-login group role that owns the public schema and
// every app object, so either rotation role can use them.
const NeonGroupRole = "envbank_app_owner"

// DefaultNeonRoles are the rotation roles when params name none.
var DefaultNeonRoles = [2]string{"app_a", "app_b"}

// NeonProjectSpec describes a project to create. All fields are validated.
type NeonProjectSpec struct {
	Name      string
	RegionID  string // empty: the provider default
	PGVersion int    // 0: the provider default
}

// NeonProject identifies a created project (no values). Role is the
// project's default (owner) role.
type NeonProject struct {
	ProjectID string
	BranchID  string
	Role      string
	Database  string
}

// NeonPort is the Neon control-plane surface the actions need. Close ends
// the port's use of its credential: the service calls it when the operation
// ends, before it wipes the credential buffer, and the port must wipe every
// copy it made.
type NeonPort interface {
	io.Closer
	// CreateProject creates a project and writes its owner role's pooled and
	// direct connection URIs to the sinks. The broker passes discarding sinks:
	// owner credentials are never persisted.
	CreateProject(ctx context.Context, spec NeonProjectSpec, pooled, direct *lifecycle.SecretSink) (NeonProject, error)
	DeleteProject(ctx context.Context, projectID string) error
	// PrepareRotationRoles makes the two login roles rotation-ready,
	// connected as ownerRole (the project owner, through a connection URI
	// fetched on demand, kept in memory and wiped, never stored): both roles
	// exist; the no-login group role NeonGroupRole exists, owns the public
	// schema, and has both roles as members; each role has
	// `ALTER ROLE … SET role = NeonGroupRole`; and with adopt, existing
	// public-schema objects are reassigned to NeonGroupRole. Idempotent. Any
	// password a role is created with is discarded.
	PrepareRotationRoles(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string, adopt bool) error
	// RotationRolesReady reports whether PrepareRotationRoles' end state
	// holds for roles (read-only).
	RotationRolesReady(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string) (bool, error)
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

// VercelPort is the Vercel API surface the actions need. Close as for
// NeonPort.
type VercelPort interface {
	io.Closer
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
	// returns nil only for a healthy (2xx) answer. An answer showing the
	// deployment is behind Vercel deployment protection is ErrHealthProtected
	// (never bypassed).
	CheckHealth(ctx context.Context, deploymentURL, path string) error
}

// StripeWebhook is an endpoint's non-secret configuration.
type StripeWebhook struct {
	URL    string
	Events []string
}

// StripePort is the Stripe API surface the actions need (test mode only).
// Close as for NeonPort.
type StripePort interface {
	io.Closer
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
	// BindingStore keeps record bindings and Vercel provenance as encrypted
	// vault objects beside the records (binding.go).
	BindingStore
}

// ErrMissing is returned by Vault.Latest for an absent record, and by the
// BindingStore loads for an absent object.
var ErrMissing = errors.New("record not found")

// ErrHealthProtected is returned by VercelPort.CheckHealth when the
// deployment answered as protected (Vercel deployment protection, HTTP 401).
// The health step then fails with CodeHealthProtected; protection is never
// bypassed.
var ErrHealthProtected = errors.New("deployment is protected")

// CodeHealthProtected: the health check reached a deployment behind Vercel
// deployment protection (401). Nothing was invalidated; the owner either
// disables protection for the throwaway project or names a health path the
// deployment serves unprotected.
const CodeHealthProtected = "HEALTH_PROTECTED"

type authorityKey struct{}

var errNotAuthorized = errors.New("operation not authorized")

func withOperationAuthority(ctx context.Context, check func(context.Context) error) context.Context {
	return context.WithValue(ctx, authorityKey{}, check)
}

// OperationAuthority reports whether ctx belongs to a running, approved
// provider operation whose grant is still valid. Ports call it immediately
// before each provider mutation they send (for example through Vercel's
// WithMutationAuthorization): outside an operation started by the service
// it always fails.
func OperationAuthority(ctx context.Context) error {
	if ctx == nil {
		return errNotAuthorized
	}
	check, ok := ctx.Value(authorityKey{}).(func(context.Context) error)
	if !ok || check == nil {
		return errNotAuthorized
	}
	return check(ctx)
}

// ErrPromotionUnsupported is returned by VercelPort.Redeploy for a
// production target when the port cannot promote: a production redeploy is
// created staged (never aliased to the production domains), so production
// traffic would keep the old credentials, and a rotation would then
// invalidate them under it. The step fails with CodePromotionUnsupported
// before any deployment is created.
var ErrPromotionUnsupported = errors.New("production promotion unsupported")

// CodePromotionUnsupported: see ErrPromotionUnsupported. Nothing was
// deployed or invalidated; env vars pushed earlier in the operation stay.
const CodePromotionUnsupported = "PRODUCTION_PROMOTION_UNSUPPORTED"
