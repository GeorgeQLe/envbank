//go:build !(darwin && cgo)

package ownerinput

import (
	"errors"
	"time"
)

func xpcRequest(string, string, xpcMessage, time.Duration) (xpcReply, error) {
	return xpcReply{}, errors.New(CodeUnavailable)
}
