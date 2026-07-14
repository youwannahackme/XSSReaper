package fixtures

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
)

// Server represents the verification fixture test server covering all XSS contexts.
type Server struct {
	HTTPServer      *httptest.Server
	ThrottleCount   atomic.Int32
	ThrottleLimit   int32
	ThrottleRecover time.Time
}

// NewHandler creates an http.Handler with all verification fixture endpoints.
func NewHandler() http.Handler {
	s := &Server{
		ThrottleLimit: 5,
	}
	return s.setupMux()
}

// NewServer creates and starts a new verification fixture HTTP server.
func NewServer() *Server {
	s := &Server{
		ThrottleLimit: 5,
	}
	s.HTTPServer = httptest.NewServer(s.setupMux())
	return s
}

func (s *Server) setupMux() http.Handler {
	mux := http.NewServeMux()

	// 1. Unencoded HTML body reflection
	mux.HandleFunc("/body", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Body Test</title></head><body><h1>Search Results</h1><div id="content">%s</div></body></html>`, q)
	})

	// 2. HTML-encoded body reflection
	mux.HandleFunc("/body-encoded", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Encoded Test</title></head><body><h1>Search Results</h1><div id="content">%s</div></body></html>`, html.EscapeString(q))
	})

	// 3. Double-quoted attribute reflection
	mux.HandleFunc("/attr-double", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><input type="text" name="search" value="%s"></body></html>`, q)
	})

	// 4. Single-quoted attribute reflection
	mux.HandleFunc("/attr-single", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><input type='text' name='search' value='%s'></body></html>`, q)
	})

	// 5. Unquoted attribute reflection
	mux.HandleFunc("/attr-unquoted", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><div class=%s id="test">Content</div></body></html>`, q)
	})

	// 6. JS string-literal context inside <script>
	mux.HandleFunc("/script-string", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><script>var searchQuery = "%s";</script></body></html>`, q)
	})

	// 7. Bare-JS context inside <script>
	mux.HandleFunc("/script-bare", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><script>var config = %s;</script></body></html>`, q)
	})

	// 8. DOM-sink case: reflects nothing server-side, ships JS writing param to innerHTML
	mux.HandleFunc("/dom-innerhtml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>DOM Sink Test</title></head>
<body>
  <h1>DOM InnerHTML Sink</h1>
  <div id="output">Default</div>
  <script>
    const params = new URLSearchParams(window.location.search);
    const q = params.get('q');
    if (q) {
      document.getElementById('output').innerHTML = q;
    }
  </script>
</body>
</html>`)
	})

	// 9. URL/href context (reachable via javascript: scheme)
	mux.HandleFunc("/url-href", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><a id="link" href="%s">Next Page</a></body></html>`, q)
	})

	// 10. JSON response field reflection
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{
			"status": "ok",
			"query":  q,
		}
		json.NewEncoder(w).Encode(resp)
	})

	// 11. HTML comment context
	mux.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><!-- User input: %s --><div>Page content</div></body></html>`, q)
	})

	// 12. CSP-protected variant of executable body context
	mux.HandleFunc("/csp-blocked", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><div id="content">%s</div></body></html>`, q)
	})

	// 13. False-positive trap: naturally echoes canary-like strings in baseline response
	mux.HandleFunc("/false-positive", func(w http.ResponseWriter, r *http.Request) {
		q := getParam(r, "q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Always include static canary-like strings in baseline, and if q is provided and matches lookalike pattern or echoes natural token
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><div id="token">Xs9k2Lp4Qr</div><div id="echo">%s</div></body></html>`, q)
	})

	// 14. Throttling endpoint: returns 429 Too Many Requests after ThrottleLimit requests
	mux.HandleFunc("/throttle", func(w http.ResponseWriter, r *http.Request) {
		count := s.ThrottleCount.Add(1)
		if count > s.ThrottleLimit {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Rate limit exceeded")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>OK</body></html>`)
	})

	// 14b. Rate limit endpoint returning 429
	mux.HandleFunc("/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		count := s.ThrottleCount.Add(1)
		if count > s.ThrottleLimit {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Rate limit exceeded")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>OK</body></html>`)
	})

	// 14c. Server error endpoint returning 500
	mux.HandleFunc("/server-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Internal Server Error")
	})

	// 15. Reset throttle counter endpoint for deterministic testing
	mux.HandleFunc("/throttle/reset", func(w http.ResponseWriter, r *http.Request) {
		s.ThrottleCount.Store(0)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Reset OK")
	})

	return mux
}

// Close shuts down the fixture HTTP server.
func (s *Server) Close() {
	if s.HTTPServer != nil {
		s.HTTPServer.Close()
	}
}

// URL returns the base URL of the fixture server.
func (s *Server) URL() string {
	return s.HTTPServer.URL
}

// getParam extracts parameter "q" from GET query or POST form/json.
func getParam(r *http.Request, name string) string {
	if val := r.URL.Query().Get(name); val != "" {
		return val
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") == "application/json" {
			var m map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&m); err == nil {
				if v, ok := m[name]; ok {
					return fmt.Sprintf("%v", v)
				}
			}
		} else {
			r.ParseForm()
			return r.FormValue(name)
		}
	}
	return ""
}
