package tier3

import (
	"context"
	"testing"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

func TestConfirmExecutionAgainstFixtures(t *testing.T) {
	srv := fixtures.NewServer()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. HTML Body unencoded -> Confirmed
	fBody := &models.Finding{
		TargetURL:      srv.URL() + "/body?q=test",
		InjectionPoint: models.InjectionQueryParam,
		ParamName:      "q",
		Context:        models.ContextHTMLBody,
		Confidence:     models.ConfidencePotential,
	}

	confBody, err := ConfirmExecution(ctx, fBody, false, "", false)
	if err != nil {
		t.Fatalf("ConfirmExecution /body failed: %v", err)
	}
	if confBody.Confidence != models.ConfidenceConfirmed {
		t.Errorf("expected /body confidence Confirmed, got %q", confBody.Confidence)
	}

	// 2. CSP Blocked endpoint with respectCSP=true -> BlockedByCSP
	cspHeader := "default-src 'none'; script-src 'self'"
	fCSP := &models.Finding{
		TargetURL:      srv.URL() + "/csp-blocked?q=test",
		InjectionPoint: models.InjectionQueryParam,
		ParamName:      "q",
		Context:        models.ContextHTMLBody,
		CSPHeader:      &cspHeader,
		Confidence:     models.ConfidencePotential,
	}

	confCSP, err := ConfirmExecution(ctx, fCSP, true, "", false)
	if err != nil {
		t.Fatalf("ConfirmExecution /csp-blocked failed: %v", err)
	}
	if confCSP.Confidence != models.ConfidenceBlockedByCSP {
		t.Errorf("expected /csp-blocked confidence BlockedByCSP, got %q", confCSP.Confidence)
	}

	// 3. JSON context -> unchanged
	fJSON := &models.Finding{
		TargetURL:      srv.URL() + "/json?q=test",
		InjectionPoint: models.InjectionQueryParam,
		ParamName:      "q",
		Context:        models.ContextJSONResponse,
		Confidence:     models.ConfidencePotential,
	}

	confJSON, err := ConfirmExecution(ctx, fJSON, false, "", false)
	if err != nil {
		t.Fatalf("ConfirmExecution /json failed: %v", err)
	}
	if confJSON.Confidence != models.ConfidencePotential {
		t.Errorf("expected /json confidence unchanged Potential, got %q", confJSON.Confidence)
	}
}
