// Package computeruse exposes the native-host embedding point to trusted
// controllers. It is not an agent-facing permission or configuration API.
package computeruse

import (
	"github.com/GeorgeQLe/envbank/internal/nativehost"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

type Keychain = nativehost.Keychain
type Host = nativehost.Host

// NewNativeHost blocks legacy value release and credential mutations even when
// protection is nil. Connect only authenticated approved extension IPC, and
// route ALL controller observations/input through protection.Gate.Observe.
// The caller must separately qualify the Driver and human approval mechanism.
func NewNativeHost(configPath string, store Keychain, protection *protectedfill.Coordinator) *Host {
	return nativehost.NewForComputerUse(configPath, store, protection)
}
