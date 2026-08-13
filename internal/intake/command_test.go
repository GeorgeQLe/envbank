package intake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommandSourcePrivatePipeAndEnvironmentFiltering(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source := CommandSource{
		Executable: executable,
		Arguments:  []string{"-test.run=^TestCommandSourceHelper$", "--", "success"},
		Environment: append(os.Environ(),
			"INTAKE_HELPER=1",
			"ENVBANK_PASSPHRASE=must-not-reach-source",
			"INTAKE_SENTINEL=private-source-sentinel",
		),
		AllowedEnvironment: []string{"INTAKE_HELPER", "INTAKE_SENTINEL"},
	}
	raw, err := source.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(raw)
	if got, want := string(raw), `{"IMPORTED":"private-source-sentinel"}`; got != want {
		t.Fatalf("source payload = %q, want %q", got, want)
	}
	if strings.Contains(string(raw), "stderr-secret") || strings.Contains(string(raw), "must-not-reach-source") {
		t.Fatal("private source captured prohibited data")
	}
}

func TestCommandSourceReturnsFixedFailure(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = (CommandSource{
		Executable: executable,
		Arguments:  []string{"-test.run=^TestCommandSourceHelper$", "--", "failure"},
		Environment: append(os.Environ(),
			"INTAKE_HELPER=1", "INTAKE_SENTINEL=failure-secret-sentinel"),
		AllowedEnvironment: []string{"INTAKE_HELPER", "INTAKE_SENTINEL"},
	}).Read(context.Background())
	if err == nil || err.Error() != "secret source failed" || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("failure = %v", err)
	}
}

func TestCommandSourceRequiresAbsolutePath(t *testing.T) {
	_, err := (CommandSource{Executable: "provider"}).Read(context.Background())
	if err == nil || err.Error() != "secret source executable must be an absolute path" {
		t.Fatalf("error = %v", err)
	}
}

func TestCommandSourcePinsExecutableIdentity(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	source := CommandSource{Executable: executable, ExecutableSHA256: hex.EncodeToString(sum[:]), Arguments: []string{"-test.run=^TestCommandSourceHelper$", "--", "success"}, Environment: append(os.Environ(), "INTAKE_HELPER=1", "INTAKE_SENTINEL=pinned"), AllowedEnvironment: []string{"INTAKE_HELPER", "INTAKE_SENTINEL"}}
	value, err := source.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	Wipe(value)
	source.ExecutableSHA256 = strings.Repeat("0", 64)
	if _, err := source.Read(context.Background()); err == nil || err.Error() != "secret source executable identity does not match" {
		t.Fatalf("error=%v", err)
	}
}

func TestCommandSourceUsesExactEnvironmentAllowlist(t *testing.T) {
	filtered := filteredEnvironment([]string{"SAFE=ok", "SECRET=hidden", "ENVBANK_PASSPHRASE=hidden"}, []string{"SAFE", "ENVBANK_PASSPHRASE"})
	if len(filtered) != 1 || filtered[0] != "SAFE=ok" {
		t.Fatalf("filtered=%v", filtered)
	}
}

func TestCommandSourceHonorsCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = (CommandSource{
		Executable:         executable,
		Arguments:          []string{"-test.run=^TestCommandSourceHelper$", "--", "wait"},
		Environment:        append(os.Environ(), "INTAKE_HELPER=1"),
		AllowedEnvironment: []string{"INTAKE_HELPER"},
	}).Read(ctx)
	if err == nil || err.Error() != "secret source failed" {
		t.Fatalf("error = %v", err)
	}
}

func TestCommandSourceKillsOversizedProducer(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = (CommandSource{
		Executable:         executable,
		Arguments:          []string{"-test.run=^TestCommandSourceHelper$", "--", "oversize"},
		Environment:        append(os.Environ(), "INTAKE_HELPER=1"),
		AllowedEnvironment: []string{"INTAKE_HELPER"},
	}).Read(context.Background())
	if err == nil || err.Error() != "secret source output exceeds the safety limit" {
		t.Fatalf("error = %v", err)
	}
}

func TestCommandSourceHelper(t *testing.T) {
	if os.Getenv("INTAKE_HELPER") != "1" {
		return
	}
	if os.Getenv("ENVBANK_PASSPHRASE") != "" {
		fmt.Fprint(os.Stderr, "must-not-reach-source")
		os.Exit(9)
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "success":
		fmt.Fprintf(os.Stdout, `{"IMPORTED":%q}`, os.Getenv("INTAKE_SENTINEL"))
		fmt.Fprint(os.Stderr, "stderr-secret")
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stderr, os.Getenv("INTAKE_SENTINEL"))
		os.Exit(7)
	case "wait":
		time.Sleep(time.Second)
		os.Exit(0)
	case "oversize":
		_, _ = os.Stdout.Write(make([]byte, MaxSourceBytes+4096))
		os.Exit(0)
	default:
		os.Exit(8)
	}
}

func TestWipe(t *testing.T) {
	value := []byte("secret")
	Wipe(value)
	for _, character := range value {
		if character != 0 {
			t.Fatal("buffer was not wiped")
		}
	}
}
