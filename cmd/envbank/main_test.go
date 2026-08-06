package main

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestHTTPServerSecurityLimits(t *testing.T) {
	httpServer := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if httpServer.MaxHeaderBytes != 16<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", httpServer.MaxHeaderBytes, 16<<10)
	}
	if httpServer.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 5s", httpServer.ReadHeaderTimeout)
	}
}

func TestServeSIGTERMGracefulShutdown(t *testing.T) {
	if os.Getenv("ENVBANK_SERVE_SIGNAL_HELPER") == "1" {
		ctx, stop := shutdownSignalContext()
		defer stop()
		ready := os.Getenv("ENVBANK_SERVE_SIGNAL_READY")
		if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		httpServer := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
		listen := func() error {
			<-ctx.Done()
			return http.ErrServerClosed
		}
		if err := runHTTPServer(ctx, httpServer, listen); err != nil {
			t.Fatal(err)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(executable, "-test.run=^TestServeSIGTERMGracefulShutdown$")
	command.Env = append(os.Environ(),
		"ENVBANK_SERVE_SIGNAL_HELPER=1",
		"ENVBANK_SERVE_SIGNAL_READY="+ready,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatalf("server did not start: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("server did not exit successfully after SIGTERM: %v\n%s", err, output.String())
	}
}
