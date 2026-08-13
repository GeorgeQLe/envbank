// Package intake runs trusted secret-source programs behind a private pipe.
// Source stdout is consumed only in memory and is never inherited by the
// operator terminal. Source stderr is discarded because third-party tools may
// include secret material in diagnostics.
package intake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	MaxSourceBytes = 1 << 20
	DefaultTimeout = 2 * time.Minute
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CommandSource identifies an explicitly trusted executable. Arguments must
// contain only non-secret locators; command lines are visible to the OS.
type CommandSource struct {
	Executable  string
	Arguments   []string
	Environment []string
	// AllowedEnvironment contains exact variable names. Empty means the child
	// receives no inherited environment.
	AllowedEnvironment []string
	ExecutableSHA256   string
	Timeout            time.Duration
}

// Read executes the source with no stdin and captures one bounded payload from
// its private stdout pipe. It deliberately discards all child diagnostics and
// returns only fixed errors.
func (source CommandSource) Read(ctx context.Context) ([]byte, error) {
	if ctx == nil || source.Executable == "" || !strings.HasPrefix(source.Executable, "/") {
		return nil, errors.New("secret source executable must be an absolute path")
	}
	if source.ExecutableSHA256 != "" {
		if !sha256Pattern.MatchString(source.ExecutableSHA256) || !matchesExecutable(source.Executable, source.ExecutableSHA256) {
			return nil, errors.New("secret source executable identity does not match")
		}
	}
	timeout := source.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 || timeout > 15*time.Minute {
		return nil, errors.New("secret source timeout is invalid")
	}
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(childCtx, source.Executable, source.Arguments...)
	command.Env = filteredEnvironment(source.Environment, source.AllowedEnvironment)
	command.Stdin = nil
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("secret source could not be prepared")
	}
	if err := command.Start(); err != nil {
		return nil, errors.New("secret source could not be started")
	}
	raw, readErr := io.ReadAll(io.LimitReader(stdout, MaxSourceBytes+1))
	if readErr != nil || len(raw) > MaxSourceBytes {
		_ = command.Process.Kill()
		_ = command.Wait()
		wipe(raw)
		if len(raw) > MaxSourceBytes {
			return nil, errors.New("secret source output exceeds the safety limit")
		}
		return nil, errors.New("secret source failed")
	}
	waitErr := command.Wait()
	if waitErr != nil {
		wipe(raw)
		return nil, errors.New("secret source failed")
	}
	return raw, nil
}

func filteredEnvironment(environment, allowed []string) []string {
	allow := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		if name != "" && !strings.HasPrefix(name, "ENVBANK_") {
			allow[name] = true
		}
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if !allow[name] || strings.HasPrefix(name, "ENVBANK_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func matchesExecutable(path, expected string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20)); err != nil {
		return false
	}
	return hex.EncodeToString(hash.Sum(nil)) == expected
}

func Wipe(value []byte) { wipe(value) }

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
