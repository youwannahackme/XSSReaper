package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

func TestWriterTableFormatNoColorInFile(t *testing.T) {
	findings := []*models.Finding{
		{
			TargetURL:   "http://example.com/search?q=test",
			ParamName:   "q",
			Context:     models.ContextHTMLBody,
			Confidence:  models.ConfidenceConfirmed,
			PayloadUsed: "<script>alert(1)</script>",
			Timestamp:   time.Now(),
		},
		{
			TargetURL:   "http://example.com/dom?q=test",
			ParamName:   "q",
			Context:     models.ContextDOMSink,
			Confidence:  models.ConfidenceDOMSink,
			PayloadUsed: "<img src=x onerror=alert(1)>",
			Timestamp:   time.Now(),
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.txt")

	if err := WriteToFile(outPath, findings, "table", false); err != nil {
		t.Fatalf("WriteToFile failed: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	raw := string(content)
	if strings.Contains(raw, "\x1b[") {
		t.Errorf("expected no ANSI color codes in file output, found ANSI sequences in: %s", raw)
	}
	if !strings.Contains(raw, "CONFIRMED") || !strings.Contains(raw, "DOM-SINK") {
		t.Errorf("expected findings in file output: %s", raw)
	}
}

func TestWriterJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "json", false)

	findings := []*models.Finding{
		{
			TargetURL:   "http://example.com/test?q=val",
			ParamName:   "q",
			Context:     models.ContextHTMLBody,
			Confidence:  models.ConfidenceConfirmed,
			PayloadUsed: "<script>1</script>",
		},
	}

	if err := w.WriteReport(findings); err != nil {
		t.Fatalf("WriteReport json failed: %v", err)
	}

	jsonStr := buf.String()
	if !strings.Contains(jsonStr, `"confidence": "confirmed"`) {
		t.Errorf("expected json output to contain confidence confirmed, got: %s", jsonStr)
	}
}
