// Package provider defines the narrow, redaction-safe boundary used by
// provider rollout adapters. Adapter implementations may inspect secret bytes
// only while servicing Write; metadata, evidence, and errors must remain safe
// to persist and display.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxProviderCodeBytes = 96

type Capabilities struct {
	Create                 bool `json:"create"`
	ReadMetadata           bool `json:"read_metadata"`
	Update                 bool `json:"update"`
	Validate               bool `json:"validate"`
	Revoke                 bool `json:"revoke"`
	SupportsIdempotencyKey bool `json:"supports_idempotency_key"`
	SupportsMaskedPresence bool `json:"supports_masked_presence"`
}

// Identity is the immutable, non-secret identity to which a credential is
// scoped. ID must not be a token, credential fingerprint, or display name.
type Identity struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
}

type Target struct {
	ProjectID     string            `json:"project_id"`
	EnvironmentID string            `json:"environment_id"`
	ServiceIDs    map[string]string `json:"service_ids"`
}

type Presence string

const (
	PresenceUnknown Presence = "unknown"
	PresenceAbsent  Presence = "absent"
	PresencePresent Presence = "present"
)

// VariableMetadata never contains a provider value or a value fingerprint.
// LastWriteKey is optional adapter evidence that a particular idempotent write
// committed; adapters must leave it empty unless the provider attests to it.
type VariableMetadata struct {
	Presence     Presence `json:"presence"`
	LastWriteKey string   `json:"last_write_key,omitempty"`
}

type MetadataState struct {
	Target    Target                                 `json:"target"`
	Variables map[string]map[string]VariableMetadata `json:"variables"`
}

type secretValue struct {
	bytes []byte
}

// SecretValue is deliberately not directly constructible. Formatting always
// redacts it and JSON serialization fails, including when it is nested in a
// WriteRequest. Use NewWriteRequest and ViewSecret at the adapter boundary.
type SecretValue struct {
	value secretValue
}

func newSecret(value []byte) SecretValue {
	return SecretValue{value: secretValue{bytes: append([]byte(nil), value...)}}
}

func (SecretValue) String() string   { return "[REDACTED]" }
func (SecretValue) GoString() string { return "[REDACTED]" }
func (SecretValue) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (SecretValue) MarshalJSON() ([]byte, error) {
	return nil, errors.New("provider secret values cannot be JSON encoded")
}

type WriteRequest struct {
	Operation      string `json:"operation"`
	Target         Target `json:"target"`
	Service        string `json:"service"`
	ServiceID      string `json:"service_id"`
	Name           string `json:"name"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	secret         SecretValue
}

func NewWriteRequest(operation string, target Target, service, serviceID, name,
	idempotencyKey string, value []byte) WriteRequest {
	return WriteRequest{Operation: operation, Target: cloneTarget(target), Service: service,
		ServiceID: serviceID, Name: name, IdempotencyKey: idempotencyKey, secret: newSecret(value)}
}

// ViewSecret limits ordinary adapter code to a callback-scoped byte view. The
// view must not be retained. Its backing bytes are cleared when Destroy runs.
func (request WriteRequest) ViewSecret(consume func([]byte) error) error {
	if consume == nil {
		return errors.New("provider secret consumer is required")
	}
	view := append([]byte(nil), request.secret.value.bytes...)
	defer func() {
		for index := range view {
			view[index] = 0
		}
	}()
	return consume(view)
}

func (request *WriteRequest) Destroy() {
	if request == nil {
		return
	}
	for index := range request.secret.value.bytes {
		request.secret.value.bytes[index] = 0
	}
	request.secret.value.bytes = nil
}

func (request WriteRequest) MarshalJSON() ([]byte, error) {
	return nil, errors.New("provider write requests cannot be JSON encoded")
}

func (request WriteRequest) String() string {
	return fmt.Sprintf("provider write %s %s/%s [secret REDACTED]", request.Operation,
		request.Service, request.Name)
}

type VerifyRequest struct {
	Target    Target `json:"target"`
	Service   string `json:"service"`
	ServiceID string `json:"service_id"`
	Name      string `json:"name"`
	WriteKey  string `json:"write_key,omitempty"`
}

type WriteEvidence struct {
	ProviderOperationID string `json:"provider_operation_id,omitempty"`
	CommittedAt         string `json:"committed_at"`
}

func (evidence WriteEvidence) Validate() error {
	if evidence.ProviderOperationID != "" &&
		(len(evidence.ProviderOperationID) > 128 || !safeCode.MatchString(evidence.ProviderOperationID)) {
		return errors.New("provider write evidence ID is invalid")
	}
	if !canonicalTimestamp(evidence.CommittedAt) {
		return errors.New("provider write evidence time is invalid")
	}
	return nil
}

type Verification string

const (
	VerificationVerified Verification = "verified"
	VerificationLimited  Verification = "limited"
)

type VerifyEvidence struct {
	Result     Verification `json:"result"`
	Presence   Presence     `json:"presence"`
	VerifiedAt string       `json:"verified_at"`
	Reason     string       `json:"reason,omitempty"`
}

func (evidence VerifyEvidence) Validate() error {
	if evidence.Result != VerificationVerified && evidence.Result != VerificationLimited {
		return errors.New("provider verification result is invalid")
	}
	if evidence.Presence != PresenceUnknown && evidence.Presence != PresenceAbsent &&
		evidence.Presence != PresencePresent {
		return errors.New("provider verification presence is invalid")
	}
	if !canonicalTimestamp(evidence.VerifiedAt) {
		return errors.New("provider verification time is invalid")
	}
	if evidence.Reason != "" && (len(evidence.Reason) > MaxProviderCodeBytes || !safeCode.MatchString(evidence.Reason)) {
		return errors.New("provider verification reason is invalid")
	}
	return nil
}

type Adapter interface {
	Capabilities() Capabilities
	Identity(context.Context) (Identity, error)
	Inspect(context.Context, Target) (MetadataState, error)
	Write(context.Context, WriteRequest) (WriteEvidence, error)
	Verify(context.Context, VerifyRequest) (VerifyEvidence, error)
}

type RetryClass string

const (
	RetryNever     RetryClass = "never"
	RetrySafe      RetryClass = "safe"
	RetryAmbiguous RetryClass = "ambiguous"
)

// Error is the only provider error representation safe to journal or print.
// Cause and response bodies are intentionally not retained or unwrapped.
type Error struct {
	Operation string     `json:"operation"`
	Status    int        `json:"status,omitempty"`
	Code      string     `json:"code,omitempty"`
	Retry     RetryClass `json:"retry"`
}

func (err Error) Error() string {
	message := "provider " + err.Operation + " failed"
	if err.Status != 0 {
		message += " (status " + strconv.Itoa(err.Status) + ")"
	}
	if err.Code != "" {
		message += " [" + err.Code + "]"
	}
	return message + "; retry=" + string(err.Retry)
}

func (err Error) Validate() error {
	if err.Operation != safeOperation(err.Operation) || err.Status != boundedStatus(err.Status) ||
		err.Code != sanitizeCode(err.Code) || err.Retry != validRetry(err.Retry) {
		return errors.New("provider error metadata is invalid")
	}
	return nil
}

var safeCode = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// NewError is intended for adapters after they have discarded response bodies.
func NewError(operation string, status int, code string, retry RetryClass) Error {
	return Error{Operation: safeOperation(operation), Status: boundedStatus(status),
		Code: sanitizeCode(code), Retry: validRetry(retry)}
}

// SanitizeError discards arbitrary error text. Typed Error metadata survives;
// all other errors become a generic, non-retryable provider failure.
func SanitizeError(operation string, err error) Error {
	var safe Error
	if errors.As(err, &safe) {
		safe.Operation = safeOperation(operation)
		safe.Status = boundedStatus(safe.Status)
		safe.Code = sanitizeCode(safe.Code)
		safe.Retry = validRetry(safe.Retry)
		return safe
	}
	var safePointer *Error
	if errors.As(err, &safePointer) && safePointer != nil {
		return NewError(operation, safePointer.Status, safePointer.Code, safePointer.Retry)
	}
	retry := RetryNever
	if safeOperation(operation) == "write" {
		// An untyped transport failure cannot prove whether a write committed.
		retry = RetryAmbiguous
	}
	return NewError(operation, 0, "", retry)
}

func cloneTarget(target Target) Target {
	cloned := target
	cloned.ServiceIDs = make(map[string]string, len(target.ServiceIDs))
	for name, id := range target.ServiceIDs {
		cloned.ServiceIDs[name] = id
	}
	return cloned
}

func safeOperation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 48 || !safeCode.MatchString(value) {
		return "request"
	}
	return value
}

func sanitizeCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxProviderCodeBytes || !safeCode.MatchString(value) {
		return ""
	}
	return value
}

func boundedStatus(status int) int {
	if status < 100 || status > 599 {
		return 0
	}
	return status
}

func validRetry(retry RetryClass) RetryClass {
	switch retry {
	case RetryNever, RetrySafe, RetryAmbiguous:
		return retry
	default:
		return RetryNever
	}
}

func canonicalTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

// Compile-time assertions keep future refactors from silently enabling JSON.
var _ json.Marshaler = SecretValue{}
var _ json.Marshaler = WriteRequest{}
