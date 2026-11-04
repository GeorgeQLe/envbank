package agentbroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultSocketPath is ~/.envbank/agent-broker/broker.sock.
func DefaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".envbank", "agent-broker", "broker.sock")
}

// Listen creates the socket in a private (0700, owned) directory and refuses
// to replace a live broker's socket.
func Listen(path string) (net.Listener, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("socket path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
		return nil, errors.New("socket directory must be a private (0700) directory owned by this user")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("socket path exists and is not a socket")
		}
		if conn, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
			conn.Close()
			return nil, errors.New("another agent broker is already listening")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve accepts connections until ctx ends. Each connection carries one request.
// `activity` is called on every accepted request (for the idle lock).
func Serve(ctx context.Context, l net.Listener, b *Broker, activity func()) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); l.Close() }()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok || !peerIsMe(uc) {
			conn.Close()
			continue
		}
		if activity != nil {
			activity()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConn(ctx, uc, b)
		}()
	}
}

func handleConn(parent context.Context, conn *net.UnixConn, b *Broker) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(io.LimitReader(conn, int64(Limits.RequestBytes)+1), 4096)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > Limits.RequestBytes {
		writeResponse(conn, refuse(CodeInvalidRequest))
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		writeResponse(conn, refuse(CodeInvalidRequest))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	// The agent hanging up cancels its request (a queued prompt is skipped; a run is killed).
	go func() {
		var one [1]byte
		_, _ = conn.Read(one[:])
		cancel()
	}()
	writeResponse(conn, b.Handle(ctx, req))
}

func writeResponse(conn net.Conn, resp Response) {
	resp.V = ProtocolVersion
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(conn).Encode(resp)
}

// Call sends one request to the broker and waits for its response (the owner
// may take a while to answer a prompt; ctx bounds the wait).
func Call(ctx context.Context, path string, req Request) (Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, errors.New(CodeBrokerDown)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	req.V = ProtocolVersion
	raw, err := json.Marshal(req)
	if err != nil || len(raw)+1 > Limits.RequestBytes {
		return Response{}, errors.New(CodeInvalidRequest)
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return Response{}, errors.New(CodeBrokerDown)
	}
	var resp Response
	dec := json.NewDecoder(io.LimitReader(conn, int64(2*Limits.ReturnBytes)+(64<<10)))
	if err := dec.Decode(&resp); err != nil {
		return Response{}, errors.New(CodeBrokerDown)
	}
	return resp, nil
}
