package vercel

import (
	"context"
	"errors"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

type mutationAuthorityKey struct{}

// WithMutationAuthorization is a trusted embedding hook, never a tool argument.
// It is checked immediately before each mutating HTTP request is sent, after
// potentially slow metadata reads. The workflow supplies signed-policy checks.
func WithMutationAuthorization(ctx context.Context, check func(context.Context) error) context.Context {
	return context.WithValue(ctx, mutationAuthorityKey{}, check)
}

type mutationNotSent struct{ safe provider.Error }

func (e mutationNotSent) Error() string { return e.safe.Error() }
func (e mutationNotSent) Unwrap() error { return e.safe }
func MutationNotSent(err error) bool    { var notSent mutationNotSent; return errors.As(err, &notSent) }
func markNotSent(err error) error {
	var safe provider.Error
	if !errors.As(err, &safe) {
		safe = provider.NewError("write", 0, "PRECONDITION_FAILED", provider.RetrySafe)
	}
	return mutationNotSent{safe: safe}
}
