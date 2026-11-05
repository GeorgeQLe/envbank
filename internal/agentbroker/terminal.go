package agentbroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
)

// TerminalPrompter asks the owner in the broker's own terminal. Agent-supplied
// text is sanitized so it cannot inject terminal control sequences to spoof a
// prompt. Secret entry never echoes.
type TerminalPrompter struct {
	In  *os.File // must be a terminal
	Out io.Writer
	// readPassword is replaceable in tests; production uses ReadHidden, which
	// disables echo before the prompt is printed.
	readPassword func(fd int) ([]byte, error)
}

// NewTerminalPrompter requires `in` to be an interactive terminal.
func NewTerminalPrompter(in *os.File, out io.Writer) (*TerminalPrompter, error) {
	if in == nil || !term.IsTerminal(int(in.Fd())) {
		return nil, errors.New("the agent broker must run in an interactive terminal (owner approvals and secret entry happen there)")
	}
	return &TerminalPrompter{In: in, Out: out}, nil
}

// NewTestTerminalPrompter builds a prompter over arbitrary files with an
// injected password reader (for tests in other packages; production code uses
// NewTerminalPrompter, which requires a real terminal).
func NewTestTerminalPrompter(in *os.File, out io.Writer, readPassword func(int) ([]byte, error)) *TerminalPrompter {
	return &TerminalPrompter{In: in, Out: out, readPassword: readPassword}
}

// Sanitize renders agent-supplied text as a single visible line: control
// characters (including ESC) and non-printing runes become \x escapes.
//
// Runs of 3+ spaces are shown as a counted marker so padding cannot push a
// payload off the visible line.
func Sanitize(s string, max int) string {
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r == ' ' {
			j := i
			for j < len(runes) && runes[j] == ' ' {
				j++
			}
			if n := j - i; n >= 3 {
				fmt.Fprintf(&b, "\\x{20}×%d", n)
				i = j - 1
				continue
			}
		}
		if r == utf8RuneError || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || !unicode.IsPrint(r) && r != ' ' {
			fmt.Fprintf(&b, "\\x{%x}", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

const utf8RuneError = '�'

// quoteArg never truncates: ResolveCommand refuses anything too long to show.
func quoteArg(a string) string {
	s := Sanitize(a, 1<<20)
	if s == "" || strings.ContainsAny(s, " \t'\"\\$`") {
		return strconv.Quote(s)
	}
	return s
}

func (p *TerminalPrompter) bell() { fmt.Fprint(p.Out, "\a") }

// ApproveRun implements Prompter.
func (p *TerminalPrompter) ApproveRun(ctx context.Context, cmd Command) (Decision, error) {
	p.bell()
	fmt.Fprintf(p.Out, "\n── EnvBank agent request: run a command with secrets ──\n")
	fmt.Fprintf(p.Out, "  executable: %s\n", quoteArg(cmd.Executable))
	fmt.Fprintf(p.Out, "              sha256 %s\n", cmd.ExecutableSHA256)
	if cmd.Interpreter != "" {
		fmt.Fprintf(p.Out, "  interpreter: %s\n               sha256 %s\n", quoteArg(cmd.Interpreter), cmd.InterpreterSHA256)
	}
	// Every argument in full, one per line, with its byte length.
	for i, a := range cmd.Args {
		fmt.Fprintf(p.Out, "  arg %-3d (%d bytes) %s\n", i+1, len(a), quoteArg(a))
	}
	for _, f := range cmd.Files {
		fmt.Fprintf(p.Out, "  file:       %s\n              sha256 %s\n", quoteArg(f.Path), f.SHA256)
	}
	fmt.Fprintf(p.Out, "  directory:  %s\n", quoteArg(cmd.Dir))
	fmt.Fprintf(p.Out, "  secrets:    %s\n", strings.Join(cmd.Secrets, ", "))
	for _, w := range cmd.Warnings {
		fmt.Fprintf(p.Out, "  WARNING:    %s\n", w)
	}
	fmt.Fprintf(p.Out, "  Output returned to the agent is redacted, but the command itself receives the values.\n")
	question := "Allow? [o]nce / [a]lways for this exact command / [N]o: "
	if !cmd.AlwaysAllowed {
		question = "Allow? [o]nce / [N]o (always is not offered for project code): "
	}
	answer, err := p.ask(ctx, question)
	if err != nil {
		return Deny, err
	}
	switch strings.ToLower(answer) {
	case "o", "once":
		return AllowOnce, nil
	case "a", "always":
		if !cmd.AlwaysAllowed {
			return AllowOnce, nil
		}
		return AllowAlways, nil
	default:
		fmt.Fprintln(p.Out, "  denied")
		return Deny, nil
	}
}

// ReadSecret implements Prompter: entered twice, never echoed.
func (p *TerminalPrompter) ReadSecret(ctx context.Context, req Ingest) ([]byte, bool, error) {
	p.bell()
	fmt.Fprintf(p.Out, "\n── EnvBank agent request: store a secret ──\n")
	fmt.Fprintf(p.Out, "  name:   %s\n", req.Name)
	fmt.Fprintf(p.Out, "  reason: %s\n", Sanitize(req.Reason, Limits.ReasonBytes))
	fmt.Fprintf(p.Out, "  The agent will learn only whether a value was stored, never the value.\n")
	if req.Replaces {
		answer, err := p.ask(ctx, "  "+req.Name+" already exists. Replace it? [y/N]: ")
		if err != nil || (strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes") {
			fmt.Fprintln(p.Out, "  denied")
			return nil, false, err
		}
	}
	first, err := p.hidden("  Enter value (hidden; empty to deny): ")
	fmt.Fprintln(p.Out)
	if err != nil || len(first) == 0 || ctx.Err() != nil {
		wipe(first)
		fmt.Fprintln(p.Out, "  denied")
		return nil, false, err
	}
	second, err := p.hidden("  Re-enter value: ")
	fmt.Fprintln(p.Out)
	defer wipe(second)
	if err != nil || !bytes.Equal(first, second) {
		wipe(first)
		fmt.Fprintln(p.Out, "  values did not match; nothing stored")
		return nil, false, err
	}
	return first, true, nil
}

// Notify implements Prompter.
func (p *TerminalPrompter) Notify(line string) {
	fmt.Fprintf(p.Out, "  [%s] %s\n", time.Now().Format("15:04:05"), Sanitize(line, 512))
}

// ask reads one line unbuffered from the terminal (so it never steals bytes
// from a later no-echo read).
func (p *TerminalPrompter) ask(ctx context.Context, prompt string) (string, error) {
	fmt.Fprint(p.Out, prompt)
	var buf []byte
	var one [1]byte
	for len(buf) < 64 {
		n, err := p.In.Read(one[:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		if one[0] == '\n' || one[0] == '\r' {
			break
		}
		buf = append(buf, one[0])
	}
	if ctx.Err() != nil {
		fmt.Fprintln(p.Out, "  (request was cancelled by the agent; ignored)")
		return "", ctx.Err()
	}
	return strings.TrimSpace(string(buf)), nil
}

// hidden prints prompt and reads a line without echo. Production disables echo
// BEFORE printing the prompt; tests inject readPassword.
func (p *TerminalPrompter) hidden(prompt string) ([]byte, error) {
	if p.readPassword != nil {
		fmt.Fprint(p.Out, prompt)
		return p.readPassword(int(p.In.Fd()))
	}
	return ReadHidden(p.In, p.Out, prompt)
}

// ConfirmPlan shows lines (each sanitized) and asks for an explicit yes.
func (p *TerminalPrompter) ConfirmPlan(ctx context.Context, title string, lines []string) (bool, error) {
	p.bell()
	fmt.Fprintf(p.Out, "\n── %s ──\n", Sanitize(title, 120))
	for _, l := range lines {
		fmt.Fprintf(p.Out, "  %s\n", Sanitize(l, 1<<12))
	}
	answer, err := p.ask(ctx, "Apply? [y/N]: ")
	if err != nil {
		return false, err
	}
	ok := strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
	if !ok {
		fmt.Fprintln(p.Out, "  declined")
	}
	return ok, nil
}

// NewPassphrase collects a new passphrase twice, never echoed. differentFrom,
// when non-nil, must not equal the result (for example the recovery passphrase
// must differ from the vault passphrase).
func (p *TerminalPrompter) NewPassphrase(ctx context.Context, title string, minBytes int, differentFrom []byte) ([]byte, bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(p.Out, "\n── %s ──\n", Sanitize(title, 120))
		first, err := p.hidden(fmt.Sprintf("  Choose a passphrase of at least %d characters (hidden; empty to cancel): ", minBytes))
		fmt.Fprintln(p.Out)
		if err != nil || len(first) == 0 || ctx.Err() != nil {
			wipe(first)
			fmt.Fprintln(p.Out, "  cancelled")
			return nil, false, err
		}
		if len(first) < minBytes || len(first) > 1024 {
			wipe(first)
			fmt.Fprintf(p.Out, "  must be %d to 1024 characters\n", minBytes)
			continue
		}
		if differentFrom != nil && bytes.Equal(first, differentFrom) {
			wipe(first)
			fmt.Fprintln(p.Out, "  must differ from the vault passphrase")
			continue
		}
		second, err := p.hidden("  Re-enter: ")
		fmt.Fprintln(p.Out)
		match := err == nil && bytes.Equal(first, second)
		wipe(second)
		if !match {
			wipe(first)
			fmt.Fprintln(p.Out, "  did not match")
			continue
		}
		return first, true, nil
	}
	return nil, false, nil
}

// AskVisible reads one visible line (for non-secret identifiers such as a
// Cloudflare Access client ID). The result is trimmed and limited to 64 bytes.
func (p *TerminalPrompter) AskVisible(ctx context.Context, prompt string) (string, error) {
	return p.ask(ctx, Sanitize(prompt, 200))
}
