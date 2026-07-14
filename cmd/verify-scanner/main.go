package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
	"github.com/youwannahackme/XSSReaper/internal/models"
	"github.com/youwannahackme/XSSReaper/internal/output"
	"github.com/youwannahackme/XSSReaper/internal/scanner"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	slog.Info("=== Phase 8: Comprehensive Verification & Evidence Collection ===")

	srv := fixtures.NewServer()
	defer srv.Close()

	slog.Info("Fixture server running", slog.String("url", srv.URL()))

	targets := []string{
		srv.URL() + "/body?q=test",
		srv.URL() + "/attr-double?q=test",
		srv.URL() + "/attr-single?q=test",
		srv.URL() + "/script-string?q=test",
		srv.URL() + "/dom-innerhtml?q=test",
		srv.URL() + "/csp-blocked?q=test",
		srv.URL() + "/json?q=test",
		srv.URL() + "/body-encoded?q=test",
		srv.URL() + "/rate-limit?q=test",
		srv.URL() + "/server-error?q=test",
	}

	cfg := scanner.Config{
		Concurrency: 5,
		Timeout:     15 * time.Second,
		Confirm:     true,
		DOM:         true,
		RespectCSP:  true,
	}

	engine := scanner.NewEngine(cfg)
	ctx := context.Background()

	slog.Info("Running scan against all verification fixture endpoints...")
	start := time.Now()
	findings, err := engine.ScanTargets(ctx, targets)
	if err != nil {
		slog.Error("Scan failed", slog.Any("error", err))
		os.Exit(1)
	}
	elapsed := time.Since(start)

	fmt.Println("\n======================= SCANNER VERIFICATION TABLE =======================")
	writer := output.NewWriter(os.Stdout, "table", false)
	writer.WriteReport(findings)
	fmt.Println("==========================================================================")

	// Save JSON evidence
	jsonPath := "verification_report.json"
	output.WriteToFile(jsonPath, findings, "json", false)
	slog.Info("Saved JSON verification report", slog.String("file", jsonPath), slog.Duration("elapsed", elapsed))

	// Verify assertions
	resultsByPath := make(map[string]models.Confidence)
	for _, f := range findings {
		u, _ := url.Parse(f.TargetURL)
		resultsByPath[u.Path] = f.Confidence
	}

	passed := true
	assertConfidence := func(endpoint string, expected models.Confidence) {
		got, ok := resultsByPath[endpoint]
		if !ok {
			if expected == "" {
				fmt.Printf("[PASS] %s -> correctly dropped (not vulnerable / safe encoding)\n", endpoint)
				return
			}
			fmt.Printf("[FAIL] %s -> expected %s, but finding was dropped\n", endpoint, expected)
			passed = false
			return
		}
		if got != expected {
			fmt.Printf("[FAIL] %s -> expected %s, got %s\n", endpoint, expected, got)
			passed = false
			return
		}
		fmt.Printf("[PASS] %s -> verified confidence: %s\n", endpoint, got)
	}

	fmt.Println("\n======================= VERIFICATION ASSERTIONS =======================")
	assertConfidence("/body", models.ConfidenceConfirmed)
	assertConfidence("/attr-double", models.ConfidenceConfirmed)
	assertConfidence("/attr-single", models.ConfidenceConfirmed)
	assertConfidence("/script-string", models.ConfidenceConfirmed)
	assertConfidence("/dom-innerhtml", models.ConfidenceConfirmed)
	assertConfidence("/csp-blocked", models.ConfidenceBlockedByCSP)
	assertConfidence("/json", models.ConfidencePotential)
	assertConfidence("/body-encoded", "") // Should be dropped due to safe encoding
	fmt.Println("=======================================================================")

	if !passed {
		slog.Error("One or more verification assertions failed!")
		os.Exit(1)
	}
	slog.Info("All Phase 8 verification assertions PASSED successfully!")
}
