package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/mattn/go-isatty"
)

// Hardware owner approval enrollment is an explicit owner-only command. It is
// never reachable through MCP or a workflow, and it never replaces a pin.
var ownerApprovalEnroll = ownerapproval.EnrollSecureEnclave
var ownerApprovalInteractive = func() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stderr.Fd())
}
var ownerApprovalConfirm = confirmOwnerEnrollment

const ownerEnrollmentPhrase = "enroll owner approval key"

func ownerApprovalCommand(args []string) error {
	if len(args) == 0 || args[0] != "enroll" && args[0] != "status" {
		return errors.New("owner-approval subcommand required: enroll, status")
	}
	fs := flag.NewFlagSet("owner-approval "+args[0], flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("owner-approval accepts no positional arguments")
	}
	if args[0] == "enroll" && !ownerApprovalInteractive() {
		// Checked before reading any config or passphrase.
		return errors.New("owner approval enrollment is owner-only and requires an interactive terminal; agents and workflows must never run it")
	}
	cfg, err := client.LoadConfig(auth.configPath)
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase(auth.passphraseFile)
	if err != nil {
		return err
	}
	defer clearBytes(passphrase)
	secrets, err := cfg.Unlock(passphrase)
	if err != nil {
		return err
	}
	pin := cfg.OwnerApprovalKey()
	if args[0] == "status" {
		if !ownerapproval.ValidPublicKey(pin) {
			fmt.Println("owner approval: not-enrolled\nvercel mutations: refused until an owner enrolls a Secure Enclave key")
			return nil
		}
		fmt.Printf("owner approval: pinned\nkey id: %s\nalgorithm: ecdsa-p256-sha256\nrequired attributes: secure-enclave, non-exportable, fresh user presence per approval\n", ownerapproval.KeyID(pin))
		return nil
	}
	if len(pin) != 0 {
		return errors.New("an owner approval key is already pinned in this config; rotation is a separate manual owner procedure")
	}
	if err = ownerApprovalConfirm(); err != nil {
		return err
	}
	public, err := ownerApprovalEnroll()
	if err != nil {
		return err
	}
	if !ownerapproval.ValidPublicKey(public) {
		return errors.New("enrolled owner approval key is invalid")
	}
	if err = cfg.SetOwnerApprovalKey(public); err != nil {
		return err
	}
	if err = cfg.Lock(secrets, passphrase); err != nil {
		return errors.New("owner approval pin could not be sealed into the encrypted config")
	}
	if err = cfg.Save(auth.configPath); err != nil {
		return errors.New("owner approval pin could not be saved")
	}
	fmt.Printf("owner approval: enrolled\nkey id: %s\n", ownerapproval.KeyID(public))
	return nil
}

func confirmOwnerEnrollment() error {
	fmt.Fprintf(os.Stderr, "This creates a non-exportable Secure Enclave P-256 key that requires fresh Touch ID or device-password presence for every EnvBank deployment approval, and pins its public key in this encrypted config. Do this only yourself, never through an agent. Type %q: ", ownerEnrollmentPhrase)
	raw := make([]byte, 64)
	n, err := os.Stdin.Read(raw)
	defer clearBytes(raw)
	if err != nil && err != io.EOF || strings.TrimSpace(string(raw[:n])) != ownerEnrollmentPhrase {
		return errors.New("owner approval enrollment cancelled")
	}
	return nil
}
