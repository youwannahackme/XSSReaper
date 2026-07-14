package browser

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/chromedp/chromedp"
)

var sem = make(chan struct{}, 2)

// Acquire blocks until a browser slot is available.
func Acquire() {
	sem <- struct{}{}
}

// Release frees a browser slot.
func Release() {
	<-sem
}

// FindExecPath returns the path to a Chrome or Edge executable on the system.
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
			`C:\Users\`+os.Getenv("USERNAME")+`\AppData\Local\Google\Chrome\Application\chrome.exe`,
		)
	} else {
		candidates = append(candidates,
			"google-chrome",
			"google-chrome-stable",
			"chromium",
			"chromium-browser",
			"/usr/bin/google-chrome",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
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
