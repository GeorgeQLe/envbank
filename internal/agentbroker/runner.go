package agentbroker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ExecRunner spawns the approved command itself: no shell, stdin from
// /dev/null, its own process group (killed as a whole on timeout or broker
// shutdown), and exactly the environment the broker built.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, cmd Command, env []string) RunResult {
	c := exec.Command(cmd.Executable, cmd.Args...)
	c.Dir = cmd.Dir
	c.Env = env
	c.Stdin = nil
	stdout := &capture{limit: Limits.CaptureBytes}
	stderr := &capture{limit: Limits.CaptureBytes}
	c.Stdout, c.Stderr = stdout, stderr
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A backgrounded grandchild holding the pipes must not keep the run (and its values) alive.
	c.WaitDelay = 2 * time.Second
	if err := c.Start(); err != nil {
		return RunResult{}
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	var err error
	timedOut := false
	select {
	case err = <-done:
	case <-ctx.Done():
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			err = <-done
		}
	}
	// Anything left in the group (backgrounded children) must not outlive the run with the values.
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	code := 0
	if err != nil {
		code = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
	}
	return RunResult{
		ExitCode: code, TimedOut: timedOut, Started: true,
		Stdout: stdout.bytes(), Stderr: stderr.bytes(), StdoutCut: stdout.cut, StderrCut: stderr.cut,
	}
}

// capture keeps at most `limit` bytes and records whether output was dropped.
type capture struct {
	mu    sync.Mutex
	buf   []byte
	limit int
	cut   bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - len(c.buf)
	if room <= 0 {
		c.cut = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf = append(c.buf, p[:room]...)
		c.cut = true
		return len(p), nil
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// BaseEnv returns the minimal non-secret environment children receive: the
// broker's own PATH/HOME/USER/locale/TMPDIR, never the agent's environment and
// never EnvBank variables.
func BaseEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, "TERM=dumb")
}

func secondsDuration(s int) time.Duration { return time.Duration(s) * time.Second }

func itoa(n int) string { return strconv.Itoa(n) }
