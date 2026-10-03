package browser

import (
	"context"
	"testing"
)

func TestAcquireWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := AcquireWithContext(ctx)
	if err == nil {
		t.Fatalf("expected error from cancelled context, got nil")
	}

	// Normal acquire and release
	ctx2 := context.Background()
	if err := AcquireWithContext(ctx2); err != nil {
		t.Fatalf("expected acquire with valid context to succeed: %v", err)
	}
	Release()
}

func TestFindExecPath(t *testing.T) {
	path := FindExecPath()
	if path == "" {
		t.Log("Note: No browser executable detected in standard candidate locations")
	} else {
		t.Logf("Detected browser executable: %s", path)
	}
}

func TestAllocatorOptions(t *testing.T) {
	opts := AllocatorOptions()
	if len(opts) == 0 {
		t.Fatalf("expected non-empty allocator options")
	}
}
