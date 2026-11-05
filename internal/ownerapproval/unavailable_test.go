//go:build !darwin || !cgo

package ownerapproval_test

import (
	"errors"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
)

func TestNonMacOSRefusesHardwareApprovalAndEnrollment(t *testing.T) {
	pin := ownerapprovaltest.New("owner").PublicKey()
	if _, err := ownerapproval.OpenSecureEnclave(pin); !errors.Is(err, ownerapproval.ErrUnavailable) {
		t.Fatal("non-macOS build offered a hardware signer")
	}
	if _, err := ownerapproval.EnrollSecureEnclave(); !errors.Is(err, ownerapproval.ErrUnavailable) {
		t.Fatal("non-macOS build offered enrollment")
	}
}
