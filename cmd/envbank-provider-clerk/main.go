// envbank-provider-clerk is a narrow secret-source helper for EnvBank.
// Its export output is intentionally usable only through a pipe.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

const (
	credentialService = "com.envbank.intake.clerk"
	maxClerkOutput    = 1 << 20
	maxWebhookSecret  = 512
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "envbank-provider-clerk:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("a command is required (supported: webhook-store, export)")
	}
	switch args[0] {
	case "webhook-store":
		return webhookStore(args[1:])
	case "export":
		return export(args[1:])
	default:
		return errors.New("unknown command")
	}
}

type identityFlags struct {
	app, instance, authorizedParty string
}

func addIdentityFlags(fs *flag.FlagSet) *identityFlags {
	identity := &identityFlags{}
	fs.StringVar(&identity.app, "app", "", "Clerk application ID")
	fs.StringVar(&identity.instance, "instance", "dev", "Clerk instance ID or dev/prod")
	fs.StringVar(&identity.authorizedParty, "authorized-party", "", "public authorized-party URL")
	return identity
}

func (identity *identityFlags) validate() error {
	if !strings.HasPrefix(identity.app, "app_") || identity.instance == "" {
		return errors.New("Clerk application and instance are required")
	}
	parsed, err := url.Parse(identity.authorizedParty)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("authorized party must be an HTTPS origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("authorized party must not contain a path")
	}
	identity.authorizedParty = parsed.Scheme + "://" + parsed.Host
	return nil
}

func webhookStore(args []string) error {
	fs := flag.NewFlagSet("webhook-store", flag.ContinueOnError)
	identity := addIdentityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("webhook-store accepts no positional arguments")
	}
	if err := identity.validate(); err != nil {
		return err
	}
	var raw []byte
	var err error
	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprint(os.Stderr, "Clerk webhook signing secret (input hidden): ")
		raw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, maxWebhookSecret+1))
	}
	if err != nil {
		return errors.New("webhook secret could not be read")
	}
	defer wipe(raw)
	secret := bytes.TrimSpace(raw)
	if len(secret) > maxWebhookSecret || !bytes.HasPrefix(secret, []byte("whsec_")) || bytes.IndexAny(secret, " \t\r\n") >= 0 {
		return errors.New("webhook secret is invalid")
	}
	if err := (keychain.SystemStore{}).Put(credentialService, credentialAccount(identity), secret); err != nil {
		return errors.New("webhook secret could not be stored in Keychain")
	}
	fmt.Println("status: webhook credential stored")
	return nil
}

func export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	identity := addIdentityFlags(fs)
	clerkPath := fs.String("clerk", "", "absolute path to the official Clerk CLI")
	timeout := fs.Duration("timeout", 2*time.Minute, "Clerk CLI timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *clerkPath == "" || !strings.HasPrefix(*clerkPath, "/") {
		return errors.New("export requires --clerk /ABSOLUTE/PATH and no positional arguments")
	}
	if err := identity.validate(); err != nil {
		return err
	}
	if isatty.IsTerminal(os.Stdout.Fd()) {
		return errors.New("refusing to write secrets to a terminal; use envbank bundle prepare-exec")
	}
	if *timeout <= 0 || *timeout > 15*time.Minute {
		return errors.New("timeout must be between zero and 15 minutes")
	}
	webhook, err := (keychain.SystemStore{}).Get(credentialService, credentialAccount(identity),
		"Use the Clerk webhook signing secret for EnvBank intake")
	if err != nil {
		return errors.New("webhook credential is unavailable")
	}
	defer wipe(webhook)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	command := exec.CommandContext(ctx, *clerkPath, "env", "pull", "--app", identity.app,
		"--instance", identity.instance, "--file", "/dev/stdout")
	command.Stdin = nil
	command.Stderr = io.Discard
	var output bytes.Buffer
	command.Stdout = &limitedWriter{destination: &output, remaining: maxClerkOutput + 1}
	if err := command.Run(); err != nil || output.Len() > maxClerkOutput {
		wipe(output.Bytes())
		return errors.New("Clerk CLI key retrieval failed")
	}
	defer wipe(output.Bytes())
	values, err := parseEnvironment(output.Bytes())
	if err != nil {
		return err
	}
	secretKey := values["CLERK_SECRET_KEY"]
	publishable := findPublishable(values)
	if !strings.HasPrefix(secretKey, "sk_") || !strings.HasPrefix(publishable, "pk_") {
		return errors.New("Clerk CLI response did not contain the required keys")
	}
	issuer, err := issuerFromPublishable(publishable)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"CLERK_ISSUER":                 issuer,
		"CLERK_AUTHORIZED_PARTIES":     identity.authorizedParty,
		"CLERK_SECRET_KEY":             secretKey,
		"CLERK_WEBHOOK_SIGNING_SECRET": string(webhook),
		"VITE_CLERK_PUBLISHABLE_KEY":   publishable,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return errors.New("secret bundle could not be written to the private pipe")
	}
	return nil
}

type limitedWriter struct {
	destination io.Writer
	remaining   int64
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.remaining {
		return 0, errors.New("output limit exceeded")
	}
	written, err := writer.destination.Write(value)
	writer.remaining -= int64(written)
	return written, err
}

func parseEnvironment(raw []byte) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || !validEnvironmentName(name) {
			continue
		}
		values[name] = strings.Trim(strings.TrimSpace(value), "\"'")
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("Clerk CLI response could not be parsed")
	}
	return values, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func findPublishable(values map[string]string) string {
	for _, name := range []string{"VITE_CLERK_PUBLISHABLE_KEY", "CLERK_PUBLISHABLE_KEY",
		"NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "PUBLIC_CLERK_PUBLISHABLE_KEY"} {
		if values[name] != "" {
			return values[name]
		}
	}
	return ""
}

func issuerFromPublishable(value string) (string, error) {
	_, encoded, ok := strings.Cut(value, "_")
	if !ok {
		return "", errors.New("Clerk publishable key is invalid")
	}
	_, encoded, ok = strings.Cut(encoded, "_")
	if !ok {
		return "", errors.New("Clerk publishable key is invalid")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("Clerk publishable key is invalid")
	}
	defer wipe(decoded)
	host := strings.TrimSuffix(string(decoded), "$")
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Hostname() == "" || parsed.Host != host || parsed.Path != "" {
		return "", errors.New("Clerk publishable key contains an invalid issuer")
	}
	return parsed.String(), nil
}

func credentialAccount(identity *identityFlags) string {
	sum := sha256.Sum256([]byte("envbank.clerk.webhook.v1\x00" + identity.app + "\x00" +
		identity.instance + "\x00" + identity.authorizedParty))
	return "v1:" + hex.EncodeToString(sum[:])
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
