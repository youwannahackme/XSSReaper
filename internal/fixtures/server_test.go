package fixtures

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFixtureServerEndpoints(t *testing.T) {
	srv := NewServer()
	defer srv.Close()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "Unencoded body",
			path:     "/body?q=CANARY",
			expected: `<div id="content">CANARY</div>`,
		},
		{
			name:     "Encoded body",
			path:     "/body-encoded?q=<CANARY>",
			expected: `&lt;CANARY&gt;`,
		},
		{
			name:     "Double-quoted attr",
			path:     "/attr-double?q=CANARY",
			expected: `value="CANARY"`,
		},
		{
			name:     "Single-quoted attr",
			path:     "/attr-single?q=CANARY",
			expected: `value='CANARY'`,
		},
		{
			name:     "Unquoted attr",
			path:     "/attr-unquoted?q=CANARY",
			expected: `class=CANARY`,
		},
		{
			name:     "Script string",
			path:     "/script-string?q=CANARY",
			expected: `var searchQuery = "CANARY";`,
		},
		{
			name:     "Script bare",
			path:     "/script-bare?q=CANARY",
			expected: `var config = CANARY;`,
		},
		{
			name:     "DOM innerHTML sink",
			path:     "/dom-innerhtml?q=CANARY",
			expected: `document.getElementById('output').innerHTML = q;`,
		},
		{
			name:     "URL href",
			path:     "/url-href?q=CANARY",
			expected: `href="CANARY"`,
		},
		{
			name:     "JSON response",
			path:     "/json?q=CANARY",
			expected: `"query":"CANARY"`,
		},
		{
			name:     "HTML comment",
			path:     "/comment?q=CANARY",
			expected: `<!-- User input: CANARY -->`,
		},
		{
			name:     "CSP blocked",
			path:     "/csp-blocked?q=CANARY",
			expected: `CANARY`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL() + tc.path)
			if err != nil {
				t.Fatalf("failed HTTP get: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected status 200, got %d", resp.StatusCode)
			}
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed reading body: %v", err)
			}
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.expected) {
				t.Errorf("expected substring %q in body %s", tc.expected, bodyStr)
			}
			if tc.name == "CSP blocked" {
				csp := resp.Header.Get("Content-Security-Policy")
				if !strings.Contains(csp, "default-src 'none'") {
					t.Errorf("expected CSP header, got %q", csp)
				}
			}
		})
	}
}

func TestFixtureServerThrottle(t *testing.T) {
	srv := NewServer()
	defer srv.Close()

	for i := 1; i <= 5; i++ {
		resp, err := http.Get(srv.URL() + "/throttle")
		if err != nil {
			t.Fatalf("req %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("req %d expected 200, got %d", i, resp.StatusCode)
		}
	}

	resp, err := http.Get(srv.URL() + "/throttle")
	if err != nil {
		t.Fatalf("req 6 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("req 6 expected 429, got %d", resp.StatusCode)
	}
}
