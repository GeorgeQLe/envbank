package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/testlab"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "envbank-testlab: failed")
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	if args[0] != "serve" {
		return errors.New("supported command: serve")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	scenario := flags.String("scenario", "full-matrix", "bundled public scenario")
	stateDir := flags.String("state-dir", "", "private test-only state directory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *scenario != "full-matrix" {
		return errors.New("unknown scenario")
	}
	directory := *stateDir
	cleanup := func() {}
	if directory == "" {
		var err error
		directory, err = os.MkdirTemp("", "envbank-testlab-")
		if err != nil {
			return err
		}
		cleanup = func() { _ = os.RemoveAll(directory) }
	}
	defer cleanup()
	abs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	lab, err := testlab.Open(abs)
	if err != nil {
		return err
	}
	defer lab.Close()
	server := mcpserver.Server{Backend: lab.Production(), Extension: lab.Extension()}
	return server.Serve(context.Background(), os.Stdin, os.Stdout)
}
