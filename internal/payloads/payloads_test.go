package payloads

import (
	"strings"
	"testing"
)

func TestGetDefaultPayloadList(t *testing.T) {
	list := GetDefaultPayloadList()
	if len(list) == 0 {
		t.Fatalf("expected non-empty default payload list from embedded txt files")
	}

	foundPolyglot := false
	for _, p := range list {
		if strings.Contains(p, "jaVasCript:") || strings.Contains(p, "alert()") {
			foundPolyglot = true
			break
		}
	}
	if !foundPolyglot {
		t.Errorf("expected to find polyglot payload in default payload list")
	}
}

func TestAdaptPayloadForNonce(t *testing.T) {
	in := `<svg/oNloAd=alert()//>`
	out := AdaptPayloadForNonce(in, "test1234")
	expected := `<svg/oNloAd=window.__xss_test1234()//>`
	if out != expected {
		t.Errorf("expected %q, got %q", expected, out)
	}
}
