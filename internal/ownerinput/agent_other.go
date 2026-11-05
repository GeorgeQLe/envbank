//go:build !(darwin && cgo)

package ownerinput

import "errors"

func dialAgentXPC(string, string) (agentConn, error) {
	return nil, errors.New(CodeUnavailable)
}
