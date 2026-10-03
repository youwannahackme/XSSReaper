package tier1

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

// Analyzer performs Tier 1 baseline diffing, canary injection, and context classification.
type Analyzer struct {
	Client           *http.Client
	Headers          []string
	OnRequestOutcome func(url string, statusCode int, err error)
}

// NewAnalyzer creates a new Tier 1 analyzer.
func NewAnalyzer(timeout time.Duration, headers []string) *Analyzer {
	return &Analyzer{
		Client: &http.Client{
			Timeout: timeout,
		},
		Headers: headers,
	}
}

// AnalyzeURL runs Tier 1 analysis on all GET query parameters of a target URL.
func (a *Analyzer) AnalyzeURL(ctx context.Context, targetURL string) ([]*models.Finding, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return nil, nil
	}

	// 1. Send clean baseline request
	baselineBody, _, err := a.fetch(ctx, u.String())
	if err != nil {
		return nil, err
	}

	var candidates []*models.Finding

	// Sort query parameters for deterministic scan order
	paramNames := make([]string, 0, len(queryParams))
	for p := range queryParams {
		paramNames = append(paramNames, p)
	}
	sort.Strings(paramNames)

	// 2. Test each parameter independently
	for _, paramName := range paramNames {
		baseCanary := GenerateCanary()
		probeCanary := GenerateProbeCanary(baseCanary)

		// Step 6: Baseline diffing. If canary already appears in baseline, discard.
		if strings.Contains(baselineBody, baseCanary) {
			continue
		}

		// Inject probe canary into this parameter
		testParams := make(url.Values)
		for k, v := range queryParams {
			if k == paramName {
				testParams.Set(k, probeCanary)
			} else {
				testParams[k] = v
			}
		}
		testURL := *u
		testURL.RawQuery = testParams.Encode()

		respBody, respHeaders, err := a.fetch(ctx, testURL.String())
		// If server crashed (e.g. 500 error due to single quote breaking SQL syntax) or canary not reflected, retry without single quote
		if err != nil || !strings.Contains(respBody, baseCanary) {
			fallbackCanary := baseCanary + "<>\""
			testParams.Set(paramName, fallbackCanary)
			testURL.RawQuery = testParams.Encode()
			fbBody, fbHeaders, fbErr := a.fetch(ctx, testURL.String())
			if fbErr == nil && strings.Contains(fbBody, baseCanary) {
				probeCanary = fallbackCanary
				respBody = fbBody
				respHeaders = fbHeaders
				err = nil
			}
		}
		if err != nil || !strings.Contains(respBody, baseCanary) {
			continue
		}

		// Extract CSP header
		var cspPtr *string
		if csp := respHeaders.Get("Content-Security-Policy"); csp != "" {
			cspPtr = &csp
		}

		// Check if JSON response
		contentType := strings.ToLower(respHeaders.Get("Content-Type"))
		if strings.Contains(contentType, "application/json") {
			if strings.Contains(respBody, baseCanary) {
				candidates = append(candidates, &models.Finding{
					TargetURL:        testURL.String(),
					InjectionPoint:   models.InjectionQueryParam,
					ParamName:        paramName,
					Context:          models.ContextJSONResponse,
					EncodingDetected: DetectEncoding(baseCanary, probeCanary, respBody),
					CSPHeader:        cspPtr,
					Confidence:       models.ConfidencePotential,
					Evidence:         truncateSnippet(respBody),
					Reason:           "Reflected (non-executable context: JSON)",
					Timestamp:        time.Now(),
				})
			}
			continue
		}

		// Parse HTML reflections
		reflections := ParseReflections([]byte(respBody), baseCanary, probeCanary)
		for _, ref := range reflections {
			// Step 8: Only unencoded or breakable reflections in executable context become Candidates
			if isExecutableCandidate(ref) {
				candidates = append(candidates, &models.Finding{
					TargetURL:        testURL.String(),
					InjectionPoint:   models.InjectionQueryParam,
					ParamName:        paramName,
					Context:          ref.Context,
					EncodingDetected: ref.Encoding,
					CSPHeader:        cspPtr,
					Confidence:       models.ConfidencePotential,
					Evidence:         ref.Snippet,
					Timestamp:        time.Now(),
				})
			}
		}
	}

	return candidates, nil
}

func isExecutableCandidate(ref ReflectionOccurrence) bool {
	if ref.Encoding == models.EncodingHTMLEnt || ref.Encoding == models.EncodingURLEnc {
		return false
	}
	switch ref.Context {
	case models.ContextHTMLBody,
		models.ContextAttrDouble,
		models.ContextAttrSingle,
		models.ContextAttrUnquoted,
		models.ContextScriptString,
		models.ContextScriptBare,
		models.ContextScriptJSON,
		models.ContextURLContext,
		models.ContextComment:
		return true
	}
	return false
}

func (a *Analyzer) fetch(ctx context.Context, reqURL string) (string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 XSS-Scanner/1.0")
	for _, h := range a.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		if a.OnRequestOutcome != nil {
			a.OnRequestOutcome(reqURL, 0, err)
		}
		return "", nil, err
	}
	defer resp.Body.Close()

	if a.OnRequestOutcome != nil {
		a.OnRequestOutcome(reqURL, resp.StatusCode, nil)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", nil, err
	}
	return string(bodyBytes), resp.Header, nil
}
