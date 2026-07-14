package tier1

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
	"github.com/youwannahackme/XSSReaper/internal/models"
)

// ReflectionOccurrence describes where and how a canary reflected in HTML.
type ReflectionOccurrence struct {
	Context       models.ContextType
	Encoding      models.EncodingType
	Snippet       string
	AttributeName string
}

// ParseReflections parses HTML using golang.org/x/net/html tokenization and locates all canary reflections.
func ParseReflections(htmlBody []byte, baseCanary, probeCanary string) []ReflectionOccurrence {
	var results []ReflectionOccurrence
	tokenizer := html.NewTokenizer(bytes.NewReader(htmlBody))

	inScript := false
	inStyle := false
	scriptType := ""
	scriptID := ""

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		raw := string(tokenizer.Raw())
		token := tokenizer.Token()

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			if strings.EqualFold(token.Data, "script") {
				inScript = true
				scriptType = ""
				scriptID = ""
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "type") {
						scriptType = strings.ToLower(attr.Val)
					}
					if strings.EqualFold(attr.Key, "id") {
						scriptID = strings.ToLower(attr.Val)
					}
				}
			} else if strings.EqualFold(token.Data, "style") {
				inStyle = true
			}

			// Check attributes for canary using raw string for accurate encoding check
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, baseCanary) {
					ctx := classifyAttributeContext(token.Data, attr.Key, raw, attr.Val)
					enc := DetectEncoding(baseCanary, probeCanary, raw)
					results = append(results, ReflectionOccurrence{
						Context:       ctx,
						Encoding:      enc,
						Snippet:       truncateSnippet(raw),
						AttributeName: attr.Key,
					})
				}
			}

		case html.EndTagToken:
			if strings.EqualFold(token.Data, "script") {
				inScript = false
			} else if strings.EqualFold(token.Data, "style") {
				inStyle = false
			}

		case html.TextToken:
			text := token.Data
			if strings.Contains(text, baseCanary) || strings.Contains(raw, baseCanary) {
				var ctx models.ContextType
				if inScript {
					ctx = classifyScriptContext(raw, baseCanary, scriptType, scriptID)
				} else if inStyle {
					ctx = models.ContextCSS
				} else {
					ctx = models.ContextHTMLBody
				}
				enc := DetectEncoding(baseCanary, probeCanary, raw)
				results = append(results, ReflectionOccurrence{
					Context:  ctx,
					Encoding: enc,
					Snippet:  truncateSnippet(raw),
				})
			}

		case html.CommentToken:
			text := token.Data
			if strings.Contains(text, baseCanary) || strings.Contains(raw, baseCanary) {
				results = append(results, ReflectionOccurrence{
					Context:  models.ContextComment,
					Encoding: DetectEncoding(baseCanary, probeCanary, raw),
					Snippet:  truncateSnippet(raw),
				})
			}
		}
	}

	return results
}

func classifyAttributeContext(_, attrKey, rawTag, _ string) models.ContextType {
	lowerKey := strings.ToLower(attrKey)
	if lowerKey == "href" || lowerKey == "src" || lowerKey == "action" || lowerKey == "formaction" {
		return models.ContextURLContext
	}

	idx := strings.Index(strings.ToLower(rawTag), lowerKey)
	if idx != -1 {
		eqIdx := strings.IndexByte(rawTag[idx:], '=')
		if eqIdx != -1 {
			rem := strings.TrimSpace(rawTag[idx+eqIdx+1:])
			if len(rem) > 0 {
				switch rem[0] {
				case '"':
					return models.ContextAttrDouble
				case '\'':
					return models.ContextAttrSingle
				default:
					return models.ContextAttrUnquoted
				}
			}
		}
	}
	return models.ContextAttrDouble
}

func classifyScriptContext(rawText, canary, scriptType, scriptID string) models.ContextType {
	if strings.Contains(scriptType, "json") || scriptID == "__next_data__" {
		return models.ContextScriptJSON
	}

	idx := strings.Index(rawText, canary)
	if idx == -1 {
		return models.ContextScriptBare
	}

	prefix := rawText[:idx]
	if isInsideQuotes(prefix) {
		return models.ContextScriptString
	}
	return models.ContextScriptBare
}

func isInsideQuotes(prefix string) bool {
	var inQuote rune
	escaped := false
	for _, r := range prefix {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			}
		} else if r == '"' || r == '\'' || r == '`' {
			inQuote = r
		}
	}
	return inQuote != 0
}

func truncateSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}
