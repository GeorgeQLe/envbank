package client

import "fmt"

// HTTPStatusError lets callers distinguish absence from a transport failure
// without parsing error strings. Message retains the existing CLI diagnostic;
// workflow/tool boundaries must replace it with fixed errors before publishing.
type HTTPStatusError struct {
	Status  int
	Message string
}

func (err HTTPStatusError) Error() string {
	if err.Message != "" {
		return fmt.Sprintf("server returned %d: %s", err.Status, err.Message)
	}
	return fmt.Sprintf("server returned %d", err.Status)
}
