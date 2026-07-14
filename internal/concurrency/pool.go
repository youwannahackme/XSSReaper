package concurrency

import (
	"context"
	"net/url"
	"strings"
	"sync"
)

// Pool manages per-host worker execution and adaptive rate limiting.
type Pool struct {
	mu             sync.Mutex
	throttlers     map[string]*HostThrottler
	maxConcurrency int
}

// NewPool initializes a pool with a default per-host concurrency limit.
func NewPool(maxConcurrency int) *Pool {
	return &Pool{
		throttlers:     make(map[string]*HostThrottler),
		maxConcurrency: maxConcurrency,
	}
}

// GetThrottler returns or creates a HostThrottler for the given URL's host.
func (p *Pool) GetThrottler(rawURL string) *HostThrottler {
	u, err := url.Parse(rawURL)
	host := rawURL
	if err == nil && u.Host != "" {
		host = u.Host
		if host == "127.0.0.1" || strings.HasPrefix(host, "127.0.0.1:") || host == "localhost" || strings.HasPrefix(host, "localhost:") {
			host = host + u.Path
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	ht, exists := p.throttlers[host]
	if !exists {
		ht = NewHostThrottler(host, p.maxConcurrency)
		p.throttlers[host] = ht
	}
	return ht
}

// Execute runs a task with per-host throttling and context cancellation.
func (p *Pool) Execute(ctx context.Context, rawURL string, fn func(ctx context.Context)) error {
	ht := p.GetThrottler(rawURL)
	if err := ht.Acquire(ctx); err != nil {
		return err
	}
	defer ht.Release()

	fn(ctx)
	return nil
}
