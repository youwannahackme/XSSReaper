package tier2

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/youwannahackme/XSSReaper/internal/browser"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

// DOMSinkHit records when a canary string is passed into a client-side sink.
type DOMSinkHit struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
}

// InstrumentDOM checks whether navigating to targetURL with canary triggers any dangerous DOM sinks.
func InstrumentDOM(ctx context.Context, targetURL string, canary string) ([]DOMSinkHit, error) {
	if err := browser.AcquireWithContext(ctx); err != nil {
		return nil, err
	}
	defer browser.Release()

	opts := browser.AllocatorOptions()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()

	chromeCtx, cancelChrome := chromedp.NewContext(allocCtx)
	defer cancelChrome()

	navCtx, cancelNav := context.WithTimeout(chromeCtx, 12*time.Second)
	defer cancelNav()

	hookScript := buildSinkHookScript(canary)

	var hits []DOMSinkHit
	err := chromedp.Run(navCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(hookScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(400*time.Millisecond),
		chromedp.Evaluate(`window.__dom_sinks_hit || []`, &hits),
	)
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// PromoteIfDOMSink promotes a finding or creates a DOM finding if a canary reached a dangerous client-side sink.
func PromoteIfDOMSink(ctx context.Context, finding *models.Finding, canary string) (*models.Finding, error) {
	testURL := finding.TargetURL
	if u, err := url.Parse(finding.TargetURL); err == nil {
		q := u.Query()
		if finding.ParamName != "" {
			q.Set(finding.ParamName, canary)
		}
		u.RawQuery = q.Encode()
		testURL = u.String()
	}

	hits, err := InstrumentDOM(ctx, testURL, canary)
	if err != nil {
		return finding, err
	}
	if len(hits) > 0 {
		sinkName := hits[0].Sink
		finding.DOMSink = &sinkName
		finding.Confidence = models.ConfidenceDOMSink
		finding.Context = models.ContextDOMSink
		finding.TargetURL = testURL
		if len(hits[0].Value) > 0 && len(finding.Evidence) == 0 {
			finding.Evidence = hits[0].Value
		}
	}
	return finding, nil
}

func buildSinkHookScript(canary string) string {
	return fmt.Sprintf(`
		(function() {
			window.__dom_sinks_hit = [];
			const canary = %q;
			function checkSink(sink, val) {
				if (typeof val === 'string' && val.indexOf(canary) !== -1) {
					window.__dom_sinks_hit.push({ sink: sink, value: val });
				}
			}

			// Hook innerHTML
			const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
			if (innerDesc && innerDesc.set) {
				const origSet = innerDesc.set;
				Object.defineProperty(Element.prototype, 'innerHTML', {
					set: function(val) {
						checkSink('innerHTML', String(val));
						return origSet.call(this, val);
					}
				});
			}

			// Hook outerHTML
			const outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
			if (outerDesc && outerDesc.set) {
				const origSet = outerDesc.set;
				Object.defineProperty(Element.prototype, 'outerHTML', {
					set: function(val) {
						checkSink('outerHTML', String(val));
						return origSet.call(this, val);
					}
				});
			}

			// Hook document.write / writeln
			const origWrite = document.write;
			document.write = function(...args) {
				args.forEach(a => checkSink('document.write', String(a)));
				return origWrite.apply(this, args);
			};
			const origWriteln = document.writeln;
			document.writeln = function(...args) {
				args.forEach(a => checkSink('document.writeln', String(a)));
				return origWriteln.apply(this, args);
			};

			// Hook eval
			const origEval = window.eval;
			window.eval = function(code) {
				checkSink('eval', String(code));
				return origEval.call(this, code);
			};

			// Hook Function
			const OrigFunc = window.Function;
			window.Function = function(...args) {
				args.forEach(a => checkSink('Function', String(a)));
				return OrigFunc.apply(this, args);
			};

			// Hook setTimeout / setInterval with string argument
			const origTimeout = window.setTimeout;
			window.setTimeout = function(fn, ...args) {
				if (typeof fn === 'string') checkSink('setTimeout', fn);
				return origTimeout.apply(this, [fn, ...args]);
			};
			const origInterval = window.setInterval;
			window.setInterval = function(fn, ...args) {
				if (typeof fn === 'string') checkSink('setInterval', fn);
				return origInterval.apply(this, [fn, ...args]);
			};

			// Hook insertAdjacentHTML
			if (Element.prototype.insertAdjacentHTML) {
				const origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
				Element.prototype.insertAdjacentHTML = function(pos, val) {
					checkSink('insertAdjacentHTML', String(val));
					return origInsertAdjacentHTML.call(this, pos, val);
				};
			}

			// Hook srcdoc on iframe elements
			try {
				if (window.HTMLIFrameElement && HTMLIFrameElement.prototype) {
					const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
					if (srcdocDesc && srcdocDesc.set) {
						const origSrcdocSet = srcdocDesc.set;
						Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
							set: function(val) {
								checkSink('srcdoc', String(val));
								return origSrcdocSet.call(this, val);
							}
						});
					}
				}
			} catch(e) {}
		})();
	`, canary)
}
