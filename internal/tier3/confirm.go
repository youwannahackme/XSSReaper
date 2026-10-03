package tier3

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/youwannahackme/XSSReaper/internal/browser"
	"github.com/youwannahackme/XSSReaper/internal/models"
	"github.com/youwannahackme/XSSReaper/internal/payloads"
	"github.com/youwannahackme/XSSReaper/internal/tier1"
)

// ConfirmExecution attempts to verify an XSS candidate using headless chromedp execution and deterministic side-effects.
func ConfirmExecution(ctx context.Context, finding *models.Finding, respectCSP bool, oobURL string, allPayloads bool, customPayloads ...[]string) (*models.Finding, error) {
	// Rule 6: JSON-context reflections are never sent to Tier 3
	if finding.Context == models.ContextJSONResponse {
		return finding, nil
	}

	// Rule 2: Respect CSP downgrade path
	if respectCSP && finding.CSPHeader != nil {
		p := tier1.ParseCSP(*finding.CSPHeader)
		if p != nil && p.BlocksInlineScript() {
			finding.Confidence = models.ConfidenceBlockedByCSP
			finding.Reason = "Execution prevented by strict Content-Security-Policy"
			return finding, nil
		}
	}

	nonce := tier1.GenerateCanary()
	testPayloads := payloads.GetPayloadsForContext(finding.Context, nonce, oobURL)
	if allPayloads {
		for _, p := range payloads.GetDefaultPayloadList() {
			testPayloads = append(testPayloads, payloads.AdaptPayloadForNonce(p, nonce))
		}
	} else if len(customPayloads) > 0 && len(customPayloads[0]) > 0 {
		for _, pSlice := range customPayloads {
			for _, p := range pSlice {
				testPayloads = append(testPayloads, payloads.AdaptPayloadForNonce(p, nonce))
			}
		}
	}

	u, err := url.Parse(finding.TargetURL)
	if err != nil {
		return finding, err
	}
	queryParams := u.Query()

	for _, payload := range testPayloads {
		testParams := make(url.Values)
		for k, v := range queryParams {
			if k == finding.ParamName {
				testParams.Set(k, payload)
			} else {
				testParams[k] = v
			}
		}
		testURL := *u
		testURL.RawQuery = testParams.Encode()

		confirmed, err := verifyInBrowser(ctx, testURL.String(), nonce)
		if err == nil && confirmed {
			finding.Confidence = models.ConfidenceConfirmed
			finding.PayloadUsed = payload
			finding.TargetURL = testURL.String()
			finding.Reason = "Confirmed via headless execution side-effect (nonce callback)"
			if !allPayloads {
				return finding, nil
			}
			// When -all-payloads is enabled, print live vulnerable output and continue brute-forcing
			fmt.Fprintf(os.Stdout, "\x1b[32;1m[✓] Vulnerable:\x1b[0m \x1b[32;1m%s   - Payload: %s (Context: %s)\x1b[0m\n", finding.TargetURL, finding.PayloadUsed, finding.Context)
			continue
		}
	}

	// Rule 5: Anything that reached Tier 3 but didn't trigger the nonce stays Potential / DOM-Sink
	if finding.PayloadUsed == "" && len(testPayloads) > 0 {
		finding.PayloadUsed = testPayloads[0]
	}
	if finding.Reason == "" {
		finding.Reason = "Candidate reflected but headless execution confirmation did not trigger side-effect"
	}
	return finding, nil
}

func verifyInBrowser(ctx context.Context, targetURL string, nonce string) (bool, error) {
	if err := browser.AcquireWithContext(ctx); err != nil {
		return false, err
	}
	defer browser.Release()

	opts := browser.AllocatorOptions()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()

	chromeCtx, cancelChrome := chromedp.NewContext(allocCtx)
	defer cancelChrome()

	navCtx, cancelNav := context.WithTimeout(chromeCtx, 12*time.Second)
	defer cancelNav()

	var dialogConfirmed bool
	chromedp.ListenTarget(chromeCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			dialogConfirmed = true
			go func() {
				_ = chromedp.Run(chromeCtx, page.HandleJavaScriptDialog(true))
			}()
		}
	})

	hookScript := fmt.Sprintf(`
		(function() {
			window.__xss_confirmed = false;
			var trigger = function() { window.__xss_confirmed = true; return true; };
			window["__xss_%s"] = trigger;
			['alert', 'prompt', 'confirm', 'open', 'print'].forEach(function(fn) {
				try { window[fn] = trigger; } catch(e){}
				try { globalThis[fn] = trigger; } catch(e){}
				try { self[fn] = trigger; } catch(e){}
				try { top[fn] = trigger; } catch(e){}
				try { parent[fn] = trigger; } catch(e){}
			});
		})();
	`, nonce)

	triggerEventsScript := `
		(function() {
			if (window.__xss_confirmed) return;
			try {
				var elem = document.activeElement || document.querySelector('input, a, button, textarea, [autofocus], [onfocus]');
				if (elem && elem.focus) { elem.focus(); }
				var evt = new MouseEvent('mouseover', { bubbles: true, cancelable: true, view: window });
				document.querySelectorAll('[onmouseover], a, img, svg, div, input, details').forEach(function(el) {
					el.dispatchEvent(evt);
				});
				window.dispatchEvent(new Event('scroll'));
				window.dispatchEvent(new Event('load'));
			} catch(e) {}
		})();
	`

	var confirmed bool
	err := chromedp.Run(navCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(hookScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Evaluate(`window.__xss_confirmed === true`, &confirmed),
	)
	if err != nil {
		return false, err
	}
	if confirmed || dialogConfirmed {
		return true, nil
	}

	// If not immediately confirmed, trigger synthetic DOM events (mouseover, focus, scroll) and poll up to 900ms more
	for i := 0; i < 3; i++ {
		_ = chromedp.Run(navCtx,
			chromedp.Evaluate(triggerEventsScript, nil),
			chromedp.Sleep(300*time.Millisecond),
			chromedp.Evaluate(`window.__xss_confirmed === true`, &confirmed),
		)
		if confirmed || dialogConfirmed {
			return true, nil
		}
	}

	return false, nil
}
