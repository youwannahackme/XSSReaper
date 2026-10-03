package tier1

import (
	"strings"
)

// CSPPolicy represents parsed Content-Security-Policy directives.
type CSPPolicy struct {
	Raw        string
	Directives map[string][]string
}

// ParseCSP parses a raw Content-Security-Policy header string.
func ParseCSP(header string) *CSPPolicy {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	p := &CSPPolicy{
		Raw:        header,
		Directives: make(map[string][]string),
	}

	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) > 0 {
			name := strings.ToLower(fields[0])
			p.Directives[name] = fields[1:]
		}
	}
	return p
}

// BlocksInlineScript checks whether the CSP would block execution of injected inline scripts.
func (p *CSPPolicy) BlocksInlineScript() bool {
	if p == nil {
		return false
	}
	sources, hasScriptSrc := p.Directives["script-src-elem"]
	if !hasScriptSrc {
		sources, hasScriptSrc = p.Directives["script-src"]
		if !hasScriptSrc {
			sources, hasScriptSrc = p.Directives["default-src"]
			if !hasScriptSrc {
				return false
			}
		}
	}

	// Check if sources contain 'none'
	for _, s := range sources {
		lower := strings.ToLower(s)
		if lower == "'none'" {
			return true
		}
	}

	// Check if 'unsafe-inline' is present
	hasUnsafeInline := false
	hasNonceOrHash := false
	hasStrictDynamic := false
	for _, s := range sources {
		lower := strings.ToLower(s)
		if lower == "'unsafe-inline'" {
			hasUnsafeInline = true
		}
		if lower == "'strict-dynamic'" {
			hasStrictDynamic = true
		}
		if strings.HasPrefix(lower, "'nonce-") || strings.HasPrefix(lower, "'sha256-") || strings.HasPrefix(lower, "'sha384-") || strings.HasPrefix(lower, "'sha512-") {
			hasNonceOrHash = true
		}
	}

	// In modern browsers, if nonces, hashes, or strict-dynamic are present, 'unsafe-inline' is ignored
	if hasNonceOrHash || hasStrictDynamic {
		return true
	}
	if !hasUnsafeInline {
		return true
	}
	return false
}
