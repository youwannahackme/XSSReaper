package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/concurrency"
	"github.com/youwannahackme/XSSReaper/internal/models"
	"github.com/youwannahackme/XSSReaper/internal/tier1"
	"github.com/youwannahackme/XSSReaper/internal/tier2"
	"github.com/youwannahackme/XSSReaper/internal/tier3"
)

// Config holds all CLI flags and operational settings for the scanner engine.
type Config struct {
	Concurrency   int
	Timeout       time.Duration
	Headers       []string
	Confirm       bool
	DOM           bool
	OOBURL        string
	RespectCSP    bool
	OnlyConfirmed bool
	AllPayloads   bool
	Payloads      []string
}

// Engine orchestrates the Tier 1 -> Tier 2 -> Tier 3 scanning pipeline across targets.
type Engine struct {
	Config   Config
	Pool     *concurrency.Pool
	Analyzer *tier1.Analyzer
}

// NewEngine creates a new scanner orchestration engine.
func NewEngine(cfg Config) *Engine {
	pool := concurrency.NewPool(cfg.Concurrency)
	analyzer := tier1.NewAnalyzer(cfg.Timeout, cfg.Headers)
	analyzer.OnRequestOutcome = func(rawURL string, statusCode int, err error) {
		pool.GetThrottler(rawURL).Observe(statusCode, err)
	}
	return &Engine{
		Config:   cfg,
		Pool:     pool,
		Analyzer: analyzer,
	}
}

// ScanTargets executes XSS scanning across a slice of target URLs using per-host adaptive concurrency.
func (e *Engine) ScanTargets(ctx context.Context, urls []string) ([]*models.Finding, error) {
	var mu sync.Mutex
	var allFindings []*models.Finding

	var wg sync.WaitGroup
	for _, targetURL := range urls {
		targetURL := targetURL
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := e.Pool.Execute(ctx, targetURL, func(ctx context.Context) {
				findings, err := e.scanSingleURL(ctx, targetURL)
				if err != nil {
					slog.Debug("Error scanning target", slog.String("url", targetURL), slog.Any("error", err))
					return
				}
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
			})
			if err != nil {
				slog.Debug("Target skipped due to context cancellation or pool error", slog.String("url", targetURL), slog.Any("error", err))
			}
		}()
	}
	wg.Wait()

	return allFindings, nil
}

func (e *Engine) scanSingleURL(ctx context.Context, targetURL string) ([]*models.Finding, error) {
	fmt.Fprintf(os.Stderr, "\x1b[33;1m-> Scanning URL: %s\x1b[0m\n", targetURL)

	// Tier 1: Reflection & Context Analysis
	candidates, err := e.Analyzer.AnalyzeURL(ctx, targetURL)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 && e.Config.DOM {
		if u, parseErr := url.Parse(targetURL); parseErr == nil {
			for paramName := range u.Query() {
				domCandidate := &models.Finding{
					TargetURL:      targetURL,
					InjectionPoint: models.InjectionQueryParam,
					ParamName:      paramName,
					Context:        models.ContextDOMSink,
					Confidence:     models.ConfidencePotential,
				}
				promoted, err := tier2.PromoteIfDOMSink(ctx, domCandidate, tier1.GenerateCanary())
				if err != nil {
					slog.Error("DOM sink promotion failed", slog.String("param", paramName), slog.Any("error", err))
				}
				if err == nil && promoted != nil && promoted.DOMSink != nil {
					candidates = append(candidates, promoted)
				}
			}
		}
	}
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stdout, "\x1b[31;1m[X]\x1b[0m \x1b[36mNot Vulnerable:\x1b[0m \x1b[31m%s\x1b[0m\n", targetURL)
		return nil, nil
	}

	var results []*models.Finding

	for _, c := range candidates {
		finding := c

		// If JSON response context, do not run Tier 2/3
		if finding.Context == models.ContextJSONResponse {
			results = append(results, finding)
			e.printLiveFinding(finding)
			continue
		}

		// Tier 2: DOM-sink instrumentation (only when -dom is set)
		if e.Config.DOM && finding.DOMSink == nil {
			promoted, err := tier2.PromoteIfDOMSink(ctx, finding, tier1.GenerateCanary())
			if err != nil {
				slog.Error("DOM sink candidate promotion failed", slog.String("url", finding.TargetURL), slog.Any("error", err))
			} else {
				finding = promoted
			}
		}

		// Tier 3: Headless execution confirmation (only when -confirm is set)
		if e.Config.Confirm {
			confirmed, err := tier3.ConfirmExecution(ctx, finding, e.Config.RespectCSP, e.Config.OOBURL, e.Config.AllPayloads, e.Config.Payloads)
			if err == nil {
				finding = confirmed
			}
		}

		results = append(results, finding)
		e.printLiveFinding(finding)
	}

	return results, nil
}

func (e *Engine) printLiveFinding(finding *models.Finding) {
	if e.Config.OnlyConfirmed && finding.Confidence != models.ConfidenceConfirmed {
		return
	}
	// When -all-payloads is true and finding is confirmed, ConfirmExecution already printed every vulnerable payload live!
	if e.Config.AllPayloads && finding.Confidence == models.ConfidenceConfirmed {
		return
	}

	switch finding.Confidence {
	case models.ConfidenceConfirmed:
		fmt.Fprintf(os.Stdout, "\x1b[32;1m[✓] Vulnerable:\x1b[0m \x1b[32;1m%s   - Payload: %s (Context: %s)\x1b[0m\n", finding.TargetURL, finding.PayloadUsed, finding.Context)
	case models.ConfidenceDOMSink:
		sinkName := ""
		if finding.DOMSink != nil {
			sinkName = *finding.DOMSink
		}
		fmt.Fprintf(os.Stdout, "\x1b[33;1m[✓] DOM-Sink:\x1b[0m \x1b[33;1m%s   - Sink: %s\x1b[0m\n", finding.TargetURL, sinkName)
	case models.ConfidenceBlockedByCSP:
		fmt.Fprintf(os.Stdout, "\x1b[35;1m[BLOCKED-CSP]\x1b[0m %s (Context: %s)\n", finding.TargetURL, finding.Context)
	case models.ConfidencePotential:
		if e.Config.Confirm {
			return
		}
		fmt.Fprintf(os.Stdout, "\x1b[36;1m[POTENTIAL]\x1b[0m %s (Context: %s)\n", finding.TargetURL, finding.Context)
	default:
		fmt.Fprintf(os.Stdout, "\x1b[31;1m[X]\x1b[0m \x1b[36mNot Vulnerable:\x1b[0m \x1b[31m%s\x1b[0m\n", finding.TargetURL)
	}
}
