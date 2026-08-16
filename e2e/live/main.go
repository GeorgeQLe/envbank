// Command envbank-live-acceptance performs opt-in, local-only provider probes.
// Credentials are accepted only from macOS Keychain or a hidden TTY prompt.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
	railwayprovider "github.com/GeorgeQLe/envbank/internal/provider/railway"
	stripeprovider "github.com/GeorgeQLe/envbank/internal/provider/stripe"
	"golang.org/x/term"
)

const acceptanceMarker = "ENVBANK_ACCEPTANCE"
const credentialService = "com.envbank.acceptance"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-live: RESULT=FAIL")
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || (args[0] != "stripe" && args[0] != "railway") {
		return errors.New("provider must be stripe or railway")
	}
	if os.Getenv("ENVBANK_LIVE_ACCEPTANCE") != "1" {
		return errors.New("live acceptance is not authorized")
	}
	for _, name := range []string{"STRIPE_SECRET_KEY", "STRIPE_API_KEY", "RAILWAY_TOKEN", "RAILWAY_API_TOKEN"} {
		if os.Getenv(name) != "" {
			return errors.New("provider credentials in environment variables are forbidden")
		}
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("an interactive terminal is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	credential, err := credential(args[0])
	if err != nil {
		return err
	}
	defer wipe(credential)
	if args[0] == "stripe" {
		return stripe(ctx, credential)
	}
	return railway(ctx, credential)
}

func credential(providerName string) ([]byte, error) {
	value, err := (keychain.SystemStore{}).Get(credentialService, providerName, "Use the dedicated EnvBank acceptance credential")
	if err == nil {
		return value, nil
	}
	fmt.Fprintf(os.Stderr, "%s control credential (input hidden): ", providerName)
	value, err = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil || len(value) == 0 {
		wipe(value)
		return nil, errors.New("credential unavailable")
	}
	return value, nil
}

func requireMarked(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, acceptanceMarker) {
		return "", fmt.Errorf("%s must contain %s", name, acceptanceMarker)
	}
	return value, nil
}

func stripe(ctx context.Context, control []byte) error {
	_, err := requireMarked("STRIPE_ACCEPTANCE_TARGET", os.Getenv("STRIPE_ACCEPTANCE_TARGET"))
	if err != nil {
		return err
	}
	webhookURL := strings.TrimSpace(os.Getenv("STRIPE_ACCEPTANCE_WEBHOOK_URL"))
	if !strings.HasPrefix(webhookURL, "https://") {
		return errors.New("STRIPE_ACCEPTANCE_WEBHOOK_URL must be HTTPS")
	}
	adapter, err := stripeprovider.New(control, stripeprovider.Options{})
	if err != nil {
		return err
	}
	defer adapter.Close()
	identity, err := adapter.Identify(ctx)
	if err != nil {
		return err
	}
	recovery, err := recoveryPath("stripe")
	if err != nil {
		return err
	}
	if raw, readErr := os.ReadFile(recovery); readErr == nil {
		var prior struct {
			ResourceID string `json:"resource_id"`
		}
		if json.Unmarshal(raw, &prior) != nil || !strings.HasPrefix(prior.ResourceID, "we_") {
			return errors.New("invalid Stripe recovery state")
		}
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		revokeErr := adapter.Revoke(cleanup, prior.ResourceID)
		stop()
		if !absentOrNil(revokeErr) {
			return revokeErr
		}
		_ = os.Remove(recovery)
	}
	writer := &memoryWriter{}
	sink, _ := lifecycle.NewSecretSink(writer, "STRIPE_ACCEPTANCE_WEBHOOK_SECRET")
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	idempotency := "envbank-acceptance-" + base64.RawURLEncoding.EncodeToString(random)
	wipe(random)
	evidence, err := adapter.Create(ctx, lifecycle.CredentialRequest{ProviderIdentity: identity.ID, CredentialType: "webhook-signing-secret", DestinationRecord: "STRIPE_ACCEPTANCE_WEBHOOK_SECRET", IdempotencyKey: idempotency, Parameters: map[string][]string{"url": {webhookURL}, "enabled_events": {"checkout.session.completed"}}}, sink)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(struct {
		ResourceID string `json:"resource_id"`
	}{evidence.CredentialID})
	if err := writeRecoveryState(recovery, raw); err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if absentOrNil(adapter.Revoke(cleanup, evidence.CredentialID)) {
			_ = os.Remove(recovery)
		}
	}()
	verified, err := adapter.Validate(ctx, evidence.CredentialID)
	if err != nil || verified.Presence != provider.PresencePresent || !writer.stored {
		return errors.New("Stripe created resource could not be validated")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
	err = adapter.Revoke(cleanup, evidence.CredentialID)
	stop()
	if err != nil {
		return err
	}
	_, err = adapter.Validate(ctx, evidence.CredentialID)
	var providerErr provider.Error
	if !errors.As(err, &providerErr) || providerErr.Status != 404 {
		return errors.New("Stripe resource absence was not confirmed")
	}
	_ = os.Remove(recovery)
	fmt.Printf("e2e-live: provider=stripe account_id=%s resource_id=%s result=PASS\n", identity.ID, evidence.CredentialID)
	return nil
}

type memoryWriter struct{ stored bool }

func (writer *memoryWriter) StoreSecret(_ context.Context, _ string, provide func(func([]byte) error) error) (int64, error) {
	err := provide(func(value []byte) error {
		if !bytes.HasPrefix(value, []byte("whsec_")) {
			return errors.New("invalid captured credential")
		}
		writer.stored = true
		return nil
	})
	return 1, err
}

func railway(ctx context.Context, token []byte) error {
	project, err := requireMarked("RAILWAY_ACCEPTANCE_PROJECT", os.Getenv("RAILWAY_ACCEPTANCE_PROJECT"))
	if err != nil {
		return err
	}
	environment := strings.TrimSpace(os.Getenv("RAILWAY_ACCEPTANCE_ENVIRONMENT"))
	service := strings.TrimSpace(os.Getenv("RAILWAY_ACCEPTANCE_SERVICE"))
	projectID := strings.TrimSpace(os.Getenv("RAILWAY_ACCEPTANCE_PROJECT_ID"))
	environmentID := strings.TrimSpace(os.Getenv("RAILWAY_ACCEPTANCE_ENVIRONMENT_ID"))
	serviceID := strings.TrimSpace(os.Getenv("RAILWAY_ACCEPTANCE_SERVICE_ID"))
	if environment == "" || service == "" || projectID == "" || environmentID == "" || serviceID == "" {
		return errors.New("Railway immutable target fields are required")
	}
	adapter, err := railwayprovider.New(token, railwayprovider.Options{})
	if err != nil {
		return err
	}
	defer adapter.Close()
	target, err := adapter.Bind(ctx, railwayprovider.BindingRequest{Project: project, ProjectID: projectID, Environment: environment, EnvironmentID: environmentID, Services: map[string]string{service: serviceID}})
	if err != nil {
		return err
	}
	randomSentinel := make([]byte, 32)
	if _, err := rand.Read(randomSentinel); err != nil {
		return err
	}
	sentinel := []byte(base64.RawURLEncoding.EncodeToString(randomSentinel))
	wipe(randomSentinel)
	defer wipe(sentinel)
	request := provider.NewWriteRequest("upsert", target, service, serviceID, "ENVBANK_ACCEPTANCE_SENTINEL", "", sentinel)
	defer request.Destroy()
	if _, err := adapter.Write(ctx, request); err != nil {
		return err
	}
	verification, err := adapter.Verify(ctx, provider.VerifyRequest{Target: target, Service: service, ServiceID: serviceID, Name: "ENVBANK_ACCEPTANCE_SENTINEL"})
	if err != nil || verification.Result != provider.VerificationLimited || verification.Presence != provider.PresenceUnknown {
		return errors.New("Railway names-only verification contract changed")
	}
	fmt.Printf("e2e-live: provider=railway project_id=%s environment_id=%s service_id=%s variable=ENVBANK_ACCEPTANCE_SENTINEL verification=LIMITED_NAMES_ONLY result=PASS\n", target.ProjectID, target.EnvironmentID, target.ServiceIDs[service])
	return nil
}

func recoveryPath(providerName string) (string, error) {
	directory, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	directory = filepath.Join(directory, "EnvBank", "acceptance")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return "", err
	}
	return filepath.Join(directory, providerName+"-cleanup.json"), nil
}

func writeRecoveryState(path string, contents []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".envbank-acceptance-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	complete = true
	return nil
}
func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func absentOrNil(err error) bool {
	if err == nil {
		return true
	}
	var providerErr provider.Error
	return errors.As(err, &providerErr) && providerErr.Status == 404
}
