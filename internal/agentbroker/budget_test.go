package agentbroker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// With less than approval.MinPromptTime of the request's budget left, no
// Touch ID prompt starts: the request is answered at once with
// TIME_BUDGET_EXHAUSTED.
func TestNoPromptStartsWithTooLittleBudgetLeft(t *testing.T) {
	dir, tool := script(t, "echo ok\n")
	p := &fakePrompter{decision: approval.Approved}
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, p)
	ctx, cancel := context.WithTimeout(context.Background(), approval.MinPromptTime-time.Second)
	defer cancel()
	start := time.Now()
	r := b.Handle(ctx, Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir})
	if r.OK || r.Code != CodeTimeBudget || p.prompts() != 0 || len(p.reasons) != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("resp %+v prompts %d after %v", r, p.prompts(), time.Since(start))
	}
	if r := b.Approve(ctx, "grant x"); r.OK || r.Code != CodeTimeBudget || len(p.reasons) != 0 {
		t.Fatalf("approve: %+v", r)
	}
}

// A request queued behind another prompt is answered TIME_BUDGET_EXHAUSTED as
// soon as too little is left to prompt, not when its whole budget is gone.
func TestQueuedRequestIsAnsweredPromptlyWhenOutOfBudget(t *testing.T) {
	dir, tool := script(t, "echo ok\n")
	p := &fakePrompter{decision: approval.Approved, block: make(chan struct{})}
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, p)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // holds the owner channel
		defer wg.Done()
		b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool, "first"}, Dir: dir})
	}()
	for p.prompts() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	budget := approval.MinPromptTime + time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	start := time.Now()
	r := b.Handle(ctx, Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool, "second"}, Dir: dir})
	if took := time.Since(start); r.OK || r.Code != CodeTimeBudget || took > budget-approval.MinPromptTime+2*time.Second || p.prompts() != 1 {
		t.Fatalf("resp %+v prompts %d after %v", r, p.prompts(), took)
	}
	close(p.block)
	wg.Wait()
}

// A run's timeout_seconds is clamped to what is left of the request's
// budget (minus a reply margin); with nothing left, nothing runs.
func TestRunTimeoutIsClampedToTheRemainingBudget(t *testing.T) {
	dir := t.TempDir()
	p := &fakePrompter{decision: approval.Approved}
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, p)
	req := Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"/bin/sleep", "30"}, Dir: dir, Always: true, TimeoutSeconds: 1}
	if r := b.Handle(context.Background(), req); !r.OK || !r.TimedOut || p.prompts() != 1 {
		t.Fatalf("always approval: %+v", r)
	}
	req.TimeoutSeconds = int(Limits.MaxTimeout.Seconds())
	ctx, cancel := context.WithTimeout(context.Background(), runReplyMargin+2*time.Second)
	defer cancel()
	start := time.Now()
	r := b.Handle(ctx, req)
	dl, _ := ctx.Deadline()
	if !r.OK || !r.TimedOut || p.prompts() != 1 || !time.Now().Before(dl) || time.Since(start) > 4*time.Second {
		t.Fatalf("clamped run: %+v after %v", r, time.Since(start))
	}
	short, cancel2 := context.WithTimeout(context.Background(), runReplyMargin/2)
	defer cancel2()
	if r := b.Handle(short, req); r.OK || r.Code != CodeTimeBudget {
		t.Fatalf("out of budget run: %+v", r)
	}
}
