package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GeorgeQLe/envbank/pkg/codexhook"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

// codexHookCommand is the owner-installed Codex lifecycle hook entrypoint.
// EnvBank never installs, enables or trusts it; see integrations/codex.
func codexHookCommand(args []string) error {
	return runCodexHook(args, os.Stdin, os.Stdout)
}

func runCodexHook(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("codex-hook subcommand is required (supported: pre-tool-use, post-tool-use, capabilities, init-gate)")
	}
	switch args[0] {
	case "pre-tool-use", "post-tool-use":
		event := codexhook.PreToolUse
		if args[0] == "post-tool-use" {
			event = codexhook.PostToolUse
		}
		// Bad arguments are answered with the hook's refusal (exit 0, strict
		// JSON), never with a CLI error the runtime might treat as fail-open.
		directory, _ := codexHookGateDirectory(args[1:])
		return codexhook.Evaluate(event, directory, input, output)
	case "capabilities":
		if len(args) != 1 {
			return errors.New("codex-hook capabilities accepts no arguments")
		}
		return json.NewEncoder(output).Encode(codexhook.Describe())
	case "init-gate":
		directory, ok := codexHookGateDirectory(args[1:])
		if !ok {
			return errors.New("codex-hook init-gate requires --gate-dir ABSOLUTE_PATH")
		}
		gate, err := protectedfill.OpenGate(directory)
		if err != nil {
			return err
		}
		state := protectedfill.ProbeGate(directory)
		if err := gate.Close(); err != nil {
			return errors.New("GATE_CLOSE_FAILED")
		}
		fmt.Fprintf(output, "EnvBank protected-operation gate state: %s. No Codex hook was installed, enabled or trusted.\n", state)
		return nil
	default:
		return fmt.Errorf("unknown codex-hook subcommand %q", args[0])
	}
}

func codexHookGateDirectory(args []string) (string, bool) {
	fs := flag.NewFlagSet("codex-hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("gate-dir", "", "private absolute protected-operation gate directory")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *directory == "" {
		return "", false
	}
	return *directory, true
}
