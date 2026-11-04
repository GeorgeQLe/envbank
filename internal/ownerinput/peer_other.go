//go:build !(darwin && cgo)

package ownerinput

import (
	"errors"
	"net"
)

func peerIdentity(*net.UnixConn, string) (Identity, error) {
	return Identity{}, errors.New(CodePeerUnverified)
}
