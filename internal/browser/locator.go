package browser

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/chromedp/chromedp"
)

var sem = make(chan struct{}, 2)

// Acquire blocks until a browser slot is available.
func Acquire() {
	_ = AcquireWithContext(context.Background())
}

// AcquireWithContext blocks until a browser slot is available or ctx is cancelled.
func AcquireWithContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case sem <- struct{}{}:
		if err := ctx.Err(); err != nil {
			Release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a browser slot.
func Release() {
	select {
	case <-sem:
	default:
	}
}

// FindExecPath returns the path to a Chrome, Edge, or Brave executable on the system.
func FindExecPath() string {
	if path := os.Getenv("CHROME_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	candidates := []string{}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		)
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			candidates = append(candidates,
				filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			)
		}
		if progFiles := os.Getenv("ProgramFiles"); progFiles != "" {
			candidates = append(candidates,
				filepath.Join(progFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			)
		}
		candidates = append(candidates, "chrome.exe", "msedge.exe", "brave.exe")
	} else {
		candidates = append(candidates,
			"google-chrome",
			"google-chrome-stable",
			"chromium",
			"chromium-browser",
			"brave-browser",
			"/usr/bin/google-chrome",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		)
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

// AllocatorOptions returns standard chromedp allocator options configured with headless flags and the discovered browser path.
func AllocatorOptions() []chromedp.ExecAllocatorOption {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if path := FindExecPath(); path != "" {
		opts = append(opts, chromedp.ExecPath(path))
	}
	return opts
}
