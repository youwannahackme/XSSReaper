package scanner

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

func TestEngineScanTargetsAgainstFixtures(t *testing.T) {
	srv := fixtures.NewServer()
	defer srv.Close()

	cfg := Config{
		Concurrency: 5,
		Timeout:     5 * time.Second,
		Confirm:     true,
		RespectCSP:  true,
	}

	engine := NewEngine(cfg)
	ctx := context.Background()

	urls := []string{
		srv.URL() + "/body?q=test",
		srv.URL() + "/attr-double?q=test",
		srv.URL() + "/body-encoded?q=test",
		srv.URL() + "/csp-blocked?q=test",
		srv.URL() + "/json?q=test",
	}

	findings, err := engine.ScanTargets(ctx, urls)
	if err != nil {
		t.Fatalf("ScanTargets failed: %v", err)
	}

	foundMap := make(map[string]models.Confidence)
	for _, f := range findings {
		u, _ := url.Parse(f.TargetURL)
		foundMap[u.Path] = f.Confidence
	}

	// /body should be Confirmed
	if conf, ok := foundMap["/body"]; !ok || conf != models.ConfidenceConfirmed {
		t.Errorf("expected /body to be Confirmed, got %v (ok=%v)", conf, ok)
	}

	// /attr-double should be Confirmed
	if conf, ok := foundMap["/attr-double"]; !ok || conf != models.ConfidenceConfirmed {
		t.Errorf("expected /attr-double to be Confirmed, got %v (ok=%v)", conf, ok)
	}

	// /body-encoded should NOT be present (dropped in Tier 1)
	if conf, ok := foundMap["/body-encoded"]; ok {
		t.Errorf("expected /body-encoded to be dropped, got %v", conf)
	}

	// /csp-blocked should be BlockedByCSP
	if conf, ok := foundMap["/csp-blocked"]; !ok || conf != models.ConfidenceBlockedByCSP {
		t.Errorf("expected /csp-blocked to be BlockedByCSP, got %v (ok=%v)", conf, ok)
	}

	// /json should be Potential (non-executable JSON)
	if conf, ok := foundMap["/json"]; !ok || conf != models.ConfidencePotential {
		t.Errorf("expected /json to be Potential, got %v (ok=%v)", conf, ok)
	}
}
