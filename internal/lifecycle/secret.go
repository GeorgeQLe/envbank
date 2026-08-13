// Package lifecycle defines secret-safe credential and deployment workflows.
package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const MaxCredentialBytes = 1 << 20

// RecordWriter must durably encrypt value into the requested EnvBank record
// before returning. Implementations must not retain the callback slice.
type RecordWriter interface {
	StoreSecret(context.Context, string, func(func([]byte) error) error) (revision int64, err error)
}

type RecordReader interface {
	ReadSecret(context.Context, string, int64, func([]byte) error) error
}

// SecretSource grants callback-scoped access to one exact encrypted record
// revision. It has no method that returns or serializes the value.
type SecretSource struct {
	reader   RecordReader
	record   string
	revision int64
}

func NewSecretSource(reader RecordReader, record string, revision int64) (*SecretSource, error) {
	if reader == nil || record == "" || revision < 1 {
		return nil, errors.New("secret source binding is invalid")
	}
	return &SecretSource{reader: reader, record: record, revision: revision}, nil
}

func (source *SecretSource) WithSecret(ctx context.Context, consume func([]byte) error) error {
	if source == nil || source.reader == nil || ctx == nil || consume == nil {
		return errors.New("secret source is unavailable")
	}
	return source.reader.ReadSecret(ctx, source.record, source.revision, func(value []byte) error {
		if len(value) == 0 || len(value) > MaxCredentialBytes {
			return errors.New("encrypted record is invalid")
		}
		view := append([]byte(nil), value...)
		defer wipe(view)
		return consume(view)
	})
}

// SecretSink is callback-scoped and intentionally has no serialization
// surface. A provider Create call is not successful until Store returns a
// durable encrypted record revision.
type SecretSink struct {
	writer RecordWriter
	record string
	used   atomic.Bool
}

type SecretReceipt struct {
	Record   string `json:"record"`
	Revision int64  `json:"revision"`
}

func NewSecretSink(writer RecordWriter, record string) (*SecretSink, error) {
	if writer == nil || record == "" {
		return nil, errors.New("secret sink binding is invalid")
	}
	return &SecretSink{writer: writer, record: record}, nil
}

func (sink *SecretSink) Store(ctx context.Context, source io.Reader) (SecretReceipt, error) {
	if sink == nil || sink.writer == nil || sink.record == "" || ctx == nil || source == nil {
		return SecretReceipt{}, errors.New("secret sink is unavailable")
	}
	if !sink.used.CompareAndSwap(false, true) {
		return SecretReceipt{}, errors.New("secret sink is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(source, MaxCredentialBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxCredentialBytes {
		wipe(raw)
		return SecretReceipt{}, errors.New("provider credential could not be stored")
	}
	defer wipe(raw)
	revision, err := sink.writer.StoreSecret(ctx, sink.record, func(consume func([]byte) error) error {
		if consume == nil {
			return errors.New("record writer supplied no encrypting consumer")
		}
		view := append([]byte(nil), raw...)
		defer wipe(view)
		return consume(view)
	})
	if err != nil || revision < 1 {
		return SecretReceipt{}, errors.New("provider credential could not be stored")
	}
	return SecretReceipt{Record: sink.record, Revision: revision}, nil
}

// StoreBytes provides an adapter-friendly entry point without exposing the
// bytes in a return value. The caller remains responsible for its source copy.
func (sink *SecretSink) StoreBytes(ctx context.Context, value []byte) (SecretReceipt, error) {
	return sink.Store(ctx, bytes.NewReader(value))
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type CredentialCapability string

const (
	CapabilityAutomatic   CredentialCapability = "automatic"
	CapabilityInteractive CredentialCapability = "interactive"
	CapabilityUnsupported CredentialCapability = "unsupported"
)

type CredentialRequest struct {
	ProviderIdentity  string
	CredentialType    string
	DestinationRecord string
	IdempotencyKey    string
	Parameters        map[string][]string
}

func (request CredentialRequest) String() string {
	return fmt.Sprintf("credential %s for %s", request.CredentialType, request.ProviderIdentity)
}

type CredentialEvidence struct {
	CredentialID string        `json:"credential_id"`
	CreatedAt    string        `json:"created_at"`
	Receipt      SecretReceipt `json:"receipt"`
}

type CredentialAdapter interface {
	Identify(context.Context) (provider.Identity, error)
	Capabilities() map[string]CredentialCapability
	Create(context.Context, CredentialRequest, *SecretSink) (CredentialEvidence, error)
	Validate(context.Context, string) (provider.VerifyEvidence, error)
	Revoke(context.Context, string) error
}

type DeploymentAdapter interface {
	Inspect(context.Context, provider.Target) (provider.MetadataState, error)
	Stage(context.Context, DeploymentRequest) (DeploymentEvidence, error)
	Activate(context.Context, DeploymentEvidence) (DeploymentEvidence, error)
	Verify(context.Context, DeploymentEvidence) (HealthEvidence, error)
	Rollback(context.Context, DeploymentEvidence) (DeploymentEvidence, error)
}

type DeploymentRequest struct {
	OperationID             string
	Target                  provider.Target
	RecordRevisions         map[string]int64
	PreviousRecordRevisions map[string]int64
}
type DeploymentEvidence struct {
	DeploymentID string `json:"deployment_id"`
	Status       string `json:"status"`
	At           string `json:"at"`
}
type HealthEvidence struct {
	SuccessfulChecks int    `json:"successful_checks"`
	FirstSuccessAt   string `json:"first_success_at"`
	LastSuccessAt    string `json:"last_success_at"`
	Healthy          bool   `json:"healthy"`
}

func (evidence HealthEvidence) Validate() error {
	if !evidence.Healthy || evidence.SuccessfulChecks < 3 {
		return errors.New("deployment health evidence is insufficient")
	}
	first, err := time.Parse(time.RFC3339, evidence.FirstSuccessAt)
	if err != nil {
		return errors.New("deployment health evidence time is invalid")
	}
	last, err := time.Parse(time.RFC3339, evidence.LastSuccessAt)
	if err != nil || last.Sub(first) < 30*time.Second {
		return errors.New("deployment health evidence window is insufficient")
	}
	return nil
}
