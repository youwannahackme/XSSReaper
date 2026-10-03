package tier1

import (
	"crypto/rand"
	"html"
	"math/big"
	"net/url"
	"strings"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateCanary creates a cryptographically random 10-character alphanumeric canary string.
func GenerateCanary() string {
	result := make([]byte, 10)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		result[i] = alphanumeric[num.Int64()]
	}
	return string(result)
}

// GenerateProbeCanary returns a canary string with probe characters appended to detect encoding without triggering WAF payload signatures.
func GenerateProbeCanary(baseCanary string) string {
	return baseCanary + `<>"'`
}

// DetectEncoding determines how the probe canary was encoded in the reflection.
func DetectEncoding(baseCanary, probeCanary, reflected string) models.EncodingType {
	if strings.Contains(reflected, probeCanary) {
		return models.EncodingNone
	}
	idx := strings.Index(reflected, baseCanary)
	if idx == -1 {
		return models.EncodingStripped
	}

	after := reflected[idx+len(baseCanary):]
	if len(after) > 64 {
		after = after[:64]
	}

	// Check if probe suffix (<>"' or <>") is present unencoded
	if strings.HasPrefix(after, `<>"'`) || strings.HasPrefix(after, `<>"`) {
		return models.EncodingNone
	}

	// HTML Entity encoding check
	if strings.HasPrefix(after, "&lt;") || strings.HasPrefix(after, "&#60;") || strings.HasPrefix(after, "&#x3c;") ||
		strings.HasPrefix(after, "&#x3C;") || strings.HasPrefix(after, "&quot;") || strings.HasPrefix(after, "&#34;") ||
		strings.HasPrefix(after, "&#39;") || strings.HasPrefix(after, "&amp;") ||
		strings.Contains(reflected, html.EscapeString(probeCanary)) {
		return models.EncodingHTMLEnt
	}

	// URL Encoding check
	if strings.HasPrefix(after, "%3C") || strings.HasPrefix(after, "%3c") ||
		strings.HasPrefix(after, "%22") || strings.HasPrefix(after, "%27") ||
		strings.Contains(reflected, url.QueryEscape(probeCanary)) {
		return models.EncodingURLEnc
	}

	// JS / Unicode / Hex escaping check
	if strings.HasPrefix(after, `\"`) || strings.HasPrefix(after, `\'`) || strings.HasPrefix(after, `\x3c`) ||
		strings.HasPrefix(after, `\x3C`) || strings.HasPrefix(after, `\u003c`) || strings.HasPrefix(after, `\u003C`) ||
		strings.HasPrefix(after, `\`) {
		return models.EncodingJSEsc
	}

	return models.EncodingStripped
}
