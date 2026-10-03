package concurrency

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// HostThrottler manages concurrency and adaptive backoff for a single host.
type HostThrottler struct {
	mu                 sync.Mutex
	host               string
	maxConcurrency     int
	currentConcurrency int
	activeRequests     int
	backoffDelay       time.Duration
	consecutiveSuccess int
	cond               *sync.Cond
}

// NewHostThrottler initializes a throttler for a specific host.
func NewHostThrottler(host string, maxConcurrency int) *HostThrottler {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	ht := &HostThrottler{
		host:               host,
		maxConcurrency:     maxConcurrency,
		currentConcurrency: maxConcurrency,
	}
	ht.cond = sync.NewCond(&ht.mu)
	return ht
}

// Acquire blocks until a concurrency slot is available for the host or ctx is cancelled.
func (ht *HostThrottler) Acquire(ctx context.Context) error {
	ht.mu.Lock()
	delay := ht.backoffDelay
	ht.mu.Unlock()

	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			ht.mu.Lock()
			ht.cond.Broadcast()
			ht.mu.Unlock()
		case <-done:
		}
	}()

	for ht.activeRequests >= ht.currentConcurrency {
		if err := ctx.Err(); err != nil {
			return err
		}
		ht.cond.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	ht.activeRequests++
	return nil
}

// Release releases an acquired concurrency slot.
func (ht *HostThrottler) Release() {
	ht.mu.Lock()
	ht.activeRequests--
	ht.cond.Signal()
	ht.mu.Unlock()
}

// Observe records the outcome of an HTTP request and adapts concurrency and backoff accordingly.
func (ht *HostThrottler) Observe(statusCode int, err error) {
	if err == context.Canceled {
		return
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()

	isThrottle := statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable || err != nil
	if isThrottle {
		oldLimit := ht.currentConcurrency
		ht.currentConcurrency = ht.currentConcurrency / 2
		if ht.currentConcurrency < 1 {
			ht.currentConcurrency = 1
		}
		if ht.backoffDelay == 0 {
			ht.backoffDelay = 250 * time.Millisecond
		} else {
			ht.backoffDelay *= 2
			if ht.backoffDelay > 8*time.Second {
				ht.backoffDelay = 8 * time.Second
			}
		}
		ht.consecutiveSuccess = 0
		slog.Warn("Adaptive throttling triggered",
			slog.String("host", ht.host),
			slog.Int("status_code", statusCode),
			slog.Int("old_concurrency", oldLimit),
			slog.Int("new_concurrency", ht.currentConcurrency),
			slog.Duration("backoff_delay", ht.backoffDelay),
		)
	} else {
		ht.consecutiveSuccess++
		if ht.consecutiveSuccess >= 3 {
			ht.backoffDelay = 0
			if ht.currentConcurrency < ht.maxConcurrency {
				ht.currentConcurrency++
			}
		}
	}
	ht.cond.Broadcast()
}

// CurrentLimit returns the current dynamically adjusted concurrency limit.
func (ht *HostThrottler) CurrentLimit() int {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	return ht.currentConcurrency
}
