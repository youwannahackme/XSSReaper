package concurrency

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestHostThrottlerAdaptiveBackoff(t *testing.T) {
	ht := NewHostThrottler("example.com", 10)

	if limit := ht.CurrentLimit(); limit != 10 {
		t.Fatalf("expected initial limit 10, got %d", limit)
	}

	// Trigger 429 observation
	ht.Observe(http.StatusTooManyRequests, nil)

	if limit := ht.CurrentLimit(); limit != 5 {
		t.Fatalf("expected limit halved to 5, got %d", limit)
	}

	ht.mu.Lock()
	delay := ht.backoffDelay
	ht.mu.Unlock()
	if delay != 250*time.Millisecond {
		t.Fatalf("expected backoff delay 250ms, got %v", delay)
	}

	// Another 429 should double backoff
	ht.Observe(http.StatusTooManyRequests, nil)
	ht.mu.Lock()
	delay2 := ht.backoffDelay
	ht.mu.Unlock()
	if delay2 != 500*time.Millisecond {
		t.Fatalf("expected backoff delay doubled to 500ms, got %v", delay2)
	}

	// Observe successes to recover
	for i := 0; i < 3; i++ {
		ht.Observe(http.StatusOK, nil)
	}

	if limit := ht.CurrentLimit(); limit != 3 {
		t.Fatalf("expected limit to recover from 2 to 3, got %d", limit)
	}
	ht.mu.Lock()
	delayRecovered := ht.backoffDelay
	ht.mu.Unlock()
	if delayRecovered != 0 {
		t.Fatalf("expected backoff delay to reset to 0, got %v", delayRecovered)
	}
}

func TestHostThrottlerAcquireRelease(t *testing.T) {
	ht := NewHostThrottler("example.com", 2)
	ctx := context.Background()

	if err := ht.Acquire(ctx); err != nil {
		t.Fatalf("acquire 1 failed: %v", err)
	}
	if err := ht.Acquire(ctx); err != nil {
		t.Fatalf("acquire 2 failed: %v", err)
	}

	// Release one and acquire again
	ht.Release()
	if err := ht.Acquire(ctx); err != nil {
		t.Fatalf("acquire 3 failed: %v", err)
	}
	ht.Release()
	ht.Release()
}
