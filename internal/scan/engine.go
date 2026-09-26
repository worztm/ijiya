package scan

import (
	"context"
	"sync"
	"time"
)

// Engine runs a set of checks against a target.
type Engine struct {
	Checks      []Check
	Concurrency int
	// OnResult, when set, is called as each check finishes so callers can
	// stream progress to the terminal.
	OnResult func(CheckResult)
	// OnCheckStart, when set, is called the moment a check begins running,
	// before any of its requests go out.
	OnCheckStart func(checkID string)
	// OnFinding, when set, is called the moment a check discovers a
	// finding, before the check itself has finished. It is how live views
	// show results as they happen.
	OnFinding func(checkID string, f Finding)
}

// Run executes every check and returns the results in selection order.
func (e *Engine) Run(ctx context.Context, t *Target) []CheckResult {
	if ctx == nil {
		ctx = context.Background()
	}
	limit := e.Concurrency
	if limit < 1 {
		limit = 1
	}
	if limit > len(e.Checks) && len(e.Checks) > 0 {
		limit = len(e.Checks)
	}

	results := make([]CheckResult, len(e.Checks))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, c := range e.Checks {
		i, c := i, c
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = CheckResult{
					ID:       c.ID(),
					Name:     c.Name(),
					Category: c.Category(),
					Error:    ctx.Err().Error(),
				}
				return
			}
			defer func() { <-sem }()

			if e.OnCheckStart != nil {
				e.OnCheckStart(c.ID())
			}

			res := runCheck(ctx, c, t, e.OnFinding)
			results[i] = res
			if e.OnResult != nil {
				e.OnResult(res)
			}
		}()
	}
	wg.Wait()
	return results
}

// runCheck executes a single check and fills in its bookkeeping fields.
func runCheck(ctx context.Context, c Check, t *Target, emit func(string, Finding)) CheckResult {
	res := CheckResult{
		ID:       c.ID(),
		Name:     c.Name(),
		Category: c.Category(),
		Findings: []Finding{},
	}

	// A check may stop early when the caller cancels the scan; treat that
	// as a cancelled run rather than a failure.
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Let the caller watch findings arrive while the check is still running.
	// This is what powers the TUI's live results feed.
	if emit != nil {
		id, cat := res.ID, res.Category
		checkCtx = WithEmitter(checkCtx, func(f Finding) {
			emit(id, normaliseFinding(f, id, cat, t))
		})
	}

	start := time.Now()
	findings, err := c.Run(checkCtx, t)
	res.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		res.Error = err.Error()
	}
	for _, f := range findings {
		res.Findings = append(res.Findings, normaliseFinding(f, res.ID, res.Category, t))
	}
	return res
}

// emitKey carries the callback that streams findings to a live view.
type emitKey struct{}

// WithEmitter attaches a live-finding callback to ctx. The callback is
// invoked with the finding the instant a check discovers it, so a UI can
// show progress while the rest of the check is still running.
func WithEmitter(ctx context.Context, fn func(Finding)) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, emitKey{}, fn)
}

// Emit streams a finding when the caller installed an emitter via
// WithEmitter; it is a no-op otherwise, so checks need no special casing.
func Emit(ctx context.Context, f Finding) {
	if ctx == nil {
		return
	}
	if fn, ok := ctx.Value(emitKey{}).(func(Finding)); ok && fn != nil {
		fn(f)
	}
}

// normaliseFinding fills in the fields every finding should carry, falling
// back to the check and target that produced it.
func normaliseFinding(f Finding, checkID string, cat Category, t *Target) Finding {
	f.CheckID = checkID
	if f.Category == "" {
		f.Category = cat
	}
	if f.URL == "" {
		f.URL = t.URL.String()
	}
	return f
}
