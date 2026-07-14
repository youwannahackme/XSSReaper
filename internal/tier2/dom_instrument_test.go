package tier2

import (
	"context"
	"testing"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

func TestInstrumentDOMAgainstFixture(t *testing.T) {
	srv := fixtures.NewServer()
	defer srv.Close()

	canary := "DomCanary123"
	targetURL := srv.URL() + "/dom-innerhtml?q=" + canary

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hits, err := InstrumentDOM(ctx, targetURL, canary)
	if err != nil {
		t.Fatalf("InstrumentDOM failed: %v", err)
	}

	if len(hits) == 0 {
		t.Fatalf("expected at least 1 DOM sink hit, got 0")
	}

	if hits[0].Sink != "innerHTML" {
		t.Errorf("expected sink innerHTML, got %q", hits[0].Sink)
	}

	finding := &models.Finding{
		TargetURL:  targetURL,
		Confidence: models.ConfidencePotential,
	}

	promoted, err := PromoteIfDOMSink(ctx, finding, canary)
	if err != nil {
		t.Fatalf("PromoteIfDOMSink failed: %v", err)
	}

	if promoted.Confidence != models.ConfidenceDOMSink {
		t.Errorf("expected confidence %q, got %q", models.ConfidenceDOMSink, promoted.Confidence)
	}
	if promoted.DOMSink == nil || *promoted.DOMSink != "innerHTML" {
		t.Errorf("expected DOMSink innerHTML, got %v", promoted.DOMSink)
	}
}
