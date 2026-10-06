package scan

import (
	"context"
	"sync"
	"time"
)

// limiter spaces outbound requests so a scan cannot hammer a production host.
// A zero or negative rate disables it entirely, which is the default: the
// concurrency gate already bounds parallelism, and -rate exists for the case
// where even that is too much for the target.
//
// Unlike a plain time.Ticker this reserves each slot under a mutex, so
// concurrent callers queue up in the order they arrive and each one waits for
// its own slot instead of all slowing to the same single tick.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newLimiter builds a limiter for rate requests per second. A rate of zero or
// less, or a rate high enough to be indistinguishable from unlimited, returns
// nil so the hot path stays branch-light.
func newLimiter(rate float64) *limiter {
	if rate <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval <= 0 {
		return nil
	}
	return &limiter{interval: interval}
}

// wait blocks until this request is allowed to go out, and reports false when
// the caller's context ended first (a cancelled scan must not keep waiting).
func (l *limiter) wait(ctx context.Context) bool {
	if l == nil {
		return true
	}
	// Check before reserving a slot: a scan that has already been cancelled
	// must not sit out its delay only to fail afterwards.
	if err := ctx.Err(); err != nil {
		return false
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	slot := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(slot)
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
