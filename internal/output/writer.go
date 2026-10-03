package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

// Writer handles formatting and writing scan findings to stdout or file.
type Writer struct {
	Out           io.Writer
	Format        string
	OnlyConfirmed bool
	NoColor       bool
}

// NewWriter creates a new output writer.
func NewWriter(out io.Writer, format string, onlyConfirmed bool) *Writer {
	noColor := os.Getenv("NO_COLOR") != ""
	if out != os.Stdout && out != os.Stderr {
		noColor = true
	}
	return &Writer{
		Out:           out,
		Format:        format,
		OnlyConfirmed: onlyConfirmed,
		NoColor:       noColor,
	}
}

// WriteReport outputs all findings according to configuration.
func (w *Writer) WriteReport(findings []*models.Finding) error {
	var filtered []*models.Finding
	for _, f := range findings {
		if w.OnlyConfirmed && f.Confidence != models.ConfidenceConfirmed {
			continue
		}
		filtered = append(filtered, f)
	}

	if w.Format == "json" {
		return w.writeJSON(filtered)
	}
	return w.writeTable(filtered)
}

func (w *Writer) writeJSON(findings []*models.Finding) error {
	enc := json.NewEncoder(w.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func (w *Writer) writeTable(findings []*models.Finding) error {
	var buf strings.Builder
	tw := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "CONFIDENCE\tPARAM\tCONTEXT\tTARGET\tPAYLOAD")
	fmt.Fprintln(tw, "----------\t-----\t-------\t------\t-------")

	for _, f := range findings {
		var confStr string
		switch f.Confidence {
		case models.ConfidenceConfirmed:
			confStr = "CONFIRMED"
		case models.ConfidenceDOMSink:
			confStr = "DOM-SINK"
		case models.ConfidenceBlockedByCSP:
			confStr = "BLOCKED-CSP"
		default:
			confStr = "POTENTIAL"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", confStr, f.ParamName, f.Context, f.TargetURL, f.PayloadUsed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	rendered := buf.String()
	if !w.NoColor {
		rendered = strings.ReplaceAll(rendered, "CONFIRMED  ", "\x1b[32;1mCONFIRMED\x1b[0m  ")
		rendered = strings.ReplaceAll(rendered, "DOM-SINK   ", "\x1b[33;1mDOM-SINK\x1b[0m   ")
		rendered = strings.ReplaceAll(rendered, "BLOCKED-CSP", "\x1b[35mBLOCKED-CSP\x1b[0m")
		rendered = strings.ReplaceAll(rendered, "POTENTIAL  ", "\x1b[36mPOTENTIAL\x1b[0m  ")
	}

	_, err := fmt.Fprint(w.Out, rendered)
	return err
}

// WriteToFile writes output report to a specified filepath without ANSI colors.
func WriteToFile(filepath string, findings []*models.Finding, format string, onlyConfirmed bool) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	w := NewWriter(file, format, onlyConfirmed)
	w.NoColor = true
	return w.WriteReport(findings)
}
