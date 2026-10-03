package tier1

import (
	"context"
	"testing"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

func TestHTMLParserContextClassification(t *testing.T) {
	baseCanary := "Xs9k2Lp4Qr"
	probeCanary := GenerateProbeCanary(baseCanary)
	htmlBody := []byte(`
		<!DOCTYPE html>
		<html>
		<body>
			<div id="body">` + probeCanary + `</div>
			<input type="text" value="` + probeCanary + `">
			<input type='text' value='` + probeCanary + `'>
			<div class=` + probeCanary + `></div>
			<script>var x = "` + probeCanary + `";</script>
			<script>var y = ` + probeCanary + `;</script>
			<a href="` + probeCanary + `">Link</a>
			<!-- ` + probeCanary + ` -->
		</body>
		</html>
	`)

	refs := ParseReflections(htmlBody, baseCanary, probeCanary)
	if len(refs) < 8 {
		t.Fatalf("expected at least 8 reflections, got %d", len(refs))
	}

	foundContexts := make(map[models.ContextType]bool)
	for _, r := range refs {
		foundContexts[r.Context] = true
	}

	expectedContexts := []models.ContextType{
		models.ContextHTMLBody,
		models.ContextAttrDouble,
		models.ContextAttrSingle,
		models.ContextAttrUnquoted,
		models.ContextScriptString,
		models.ContextScriptBare,
		models.ContextURLContext,
		models.ContextComment,
	}

	for _, exp := range expectedContexts {
		if !foundContexts[exp] {
			t.Errorf("expected context %q not found in reflections", exp)
		}
	}
}

func TestCSPPolicyEvaluation(t *testing.T) {
	p1 := ParseCSP("default-src 'none'; script-src 'self'")
	if !p1.BlocksInlineScript() {
		t.Errorf("expected p1 to block inline scripts")
	}

	p2 := ParseCSP("script-src 'unsafe-inline'")
	if p2.BlocksInlineScript() {
		t.Errorf("expected p2 not to block inline scripts")
	}
}

func TestAnalyzerAgainstFixtureServer(t *testing.T) {
	srv := fixtures.NewServer()
	defer srv.Close()

	analyzer := NewAnalyzer(5*time.Second, nil)
	ctx := context.Background()

	// 1. Unencoded body -> Candidate
	findings, err := analyzer.AnalyzeURL(ctx, srv.URL()+"/body?q=test")
	if err != nil {
		t.Fatalf("AnalyzeURL /body failed: %v", err)
	}
	if len(findings) != 1 || findings[0].Context != models.ContextHTMLBody {
		t.Fatalf("expected 1 HTML body candidate, got %+v", findings)
	}

	// 2. Encoded body -> 0 candidates
	findingsEncoded, err := analyzer.AnalyzeURL(ctx, srv.URL()+"/body-encoded?q=test")
	if err != nil {
		t.Fatalf("AnalyzeURL /body-encoded failed: %v", err)
	}
	if len(findingsEncoded) != 0 {
		t.Fatalf("expected 0 candidates for encoded body, got %d", len(findingsEncoded))
	}

	// 3. JSON endpoint -> 1 JSON finding
	findingsJSON, err := analyzer.AnalyzeURL(ctx, srv.URL()+"/json?q=test")
	if err != nil {
		t.Fatalf("AnalyzeURL /json failed: %v", err)
	}
	if len(findingsJSON) != 1 || findingsJSON[0].Context != models.ContextJSONResponse {
		t.Fatalf("expected 1 JSON response finding, got %+v", findingsJSON)
	}
}

func TestDetectEncoding(t *testing.T) {
	base := "Canary1234"
	probe := GenerateProbeCanary(base) // Canary1234<>"'

	// 1. None
	if enc := DetectEncoding(base, probe, "Prefix "+probe+" Suffix"); enc != models.EncodingNone {
		t.Errorf("expected EncodingNone, got %v", enc)
	}

	// 2. HTML Entity encoded
	if enc := DetectEncoding(base, probe, "<div>"+base+"&lt;&gt;&quot;&#39;</div>"); enc != models.EncodingHTMLEnt {
		t.Errorf("expected EncodingHTMLEnt, got %v", enc)
	}

	// 3. URL encoded
	if enc := DetectEncoding(base, probe, "href="+base+"%3C%3E%22"); enc != models.EncodingURLEnc {
		t.Errorf("expected EncodingURLEnc, got %v", enc)
	}

	// 4. JS escaped
	if enc := DetectEncoding(base, probe, `var x = "`+base+`\"";`); enc != models.EncodingJSEsc {
		t.Errorf("expected EncodingJSEsc, got %v", enc)
	}

	// 5. Stripped
	if enc := DetectEncoding(base, probe, "Hello "+base+" world"); enc != models.EncodingStripped {
		t.Errorf("expected EncodingStripped, got %v", enc)
	}

	// 6. Page has &lt; elsewhere, but canary reflection is UNENCODED
	mixedPage := "<div>&lt;p&gt;Other text&lt;/p&gt;</div><input value=\"" + probe + "\">"
	if enc := DetectEncoding(base, probe, mixedPage); enc != models.EncodingNone {
		t.Errorf("expected EncodingNone for unencoded canary even with entity on page, got %v", enc)
	}
}

func TestCSPLevel3Directives(t *testing.T) {
	// script-src-elem overrides script-src
	p1 := ParseCSP("script-src 'unsafe-inline'; script-src-elem 'none'")
	if !p1.BlocksInlineScript() {
		t.Errorf("expected script-src-elem 'none' to block inline script despite script-src 'unsafe-inline'")
	}

	// strict-dynamic invalidates unsafe-inline
	p2 := ParseCSP("script-src 'strict-dynamic' 'unsafe-inline'")
	if !p2.BlocksInlineScript() {
		t.Errorf("expected 'strict-dynamic' to invalidate 'unsafe-inline'")
	}
}
