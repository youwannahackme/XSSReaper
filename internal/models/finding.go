package models

import (
	"time"
)

// Confidence represents the confidence level of an XSS finding.
type Confidence string

const (
	ConfidencePotential    Confidence = "potential"
	ConfidenceDOMSink      Confidence = "dom-sink"
	ConfidenceConfirmed    Confidence = "confirmed"
	ConfidenceBlockedByCSP Confidence = "blocked-by-csp"
)

// InjectionPointType defines where the payload/canary was injected.
type InjectionPointType string

const (
	InjectionQueryParam InjectionPointType = "query_param"
	InjectionFormParam  InjectionPointType = "form_param"
	InjectionJSONField  InjectionPointType = "json_field"
)

// ContextType classifies where the canary reflected in the response.
type ContextType string

const (
	ContextHTMLBody       ContextType = "HTML body text"
	ContextAttrDouble     ContextType = "HTML attribute (double-quoted)"
	ContextAttrSingle     ContextType = "HTML attribute (single-quoted)"
	ContextAttrUnquoted   ContextType = "HTML attribute (unquoted)"
	ContextScriptString   ContextType = "inline <script> string literal"
	ContextScriptBare     ContextType = "inline <script> bare JS"
	ContextScriptJSON     ContextType = "inline <script> JSON block"
	ContextURLContext     ContextType = "URL attribute (href/src/action)"
	ContextCSS            ContextType = "inline CSS / style"
	ContextComment        ContextType = "HTML comment"
	ContextJSONResponse   ContextType = "JSON response field"
	ContextDOMSink        ContextType = "Client-side DOM sink"
)

// EncodingType represents the encoding observed on the reflected canary.
type EncodingType string

const (
	EncodingNone     EncodingType = "none"
	EncodingHTMLEnt  EncodingType = "html-entity"
	EncodingURLEnc   EncodingType = "url-encoded"
	EncodingJSEsc    EncodingType = "js-escaped"
	EncodingBackslash EncodingType = "backslash-escaped"
	EncodingStripped EncodingType = "stripped"
)

// Finding represents a single security vulnerability or potential finding.
type Finding struct {
	TargetURL        string             `json:"target_url"`
	InjectionPoint   InjectionPointType `json:"injection_point"`
	ParamName        string             `json:"param_name"`
	Context          ContextType        `json:"context"`
	EncodingDetected EncodingType       `json:"encoding_detected"`
	DOMSink          *string            `json:"dom_sink"`
	CSPHeader        *string            `json:"csp_header"`
	PayloadUsed      string             `json:"payload_used"`
	Confidence       Confidence         `json:"confidence"`
	Evidence         string             `json:"evidence"`
	Reason           string             `json:"reason,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
}
