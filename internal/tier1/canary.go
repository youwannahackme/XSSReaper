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
	if !strings.Contains(reflected, baseCanary) {
		return models.EncodingStripped
	}
	// Base canary is present, check how the probe suffix (<>"') was encoded
	if strings.Contains(reflected, html.EscapeString(probeCanary)) || strings.Contains(reflected, "&lt;") || strings.Contains(reflected, "&#34;") {
		return models.EncodingHTMLEnt
	}
	if strings.Contains(reflected, url.QueryEscape(probeCanary)) || strings.Contains(reflected, "%3C") || strings.Contains(reflected, "%3c") {
		return models.EncodingURLEnc
	}
	if strings.Contains(reflected, `\`+baseCanary) || strings.Contains(reflected, `\"`) || strings.Contains(reflected, `\x3c`) || strings.Contains(reflected, `\u003c`) {
		return models.EncodingJSEsc
	}
	return models.EncodingStripped
}
