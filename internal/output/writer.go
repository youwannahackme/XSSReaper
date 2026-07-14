package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/youwannahackme/XSSReaper/internal/models"
)

// Writer handles formatting and writing scan findings to stdout or file.
type Writer struct {
	Out           io.Writer
	Format        string
	OnlyConfirmed bool
}

// NewWriter creates a new output writer.
func NewWriter(out io.Writer, format string, onlyConfirmed bool) *Writer {
	return &Writer{
		Out:           out,
		Format:        format,
		OnlyConfirmed: onlyConfirmed,
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
	tw := tabwriter.NewWriter(w.Out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "CONFIDENCE\tPARAM\tCONTEXT\tTARGET\tPAYLOAD")
	fmt.Fprintln(tw, "----------\t-----\t-------\t------\t-------")

	for _, f := range findings {
		confStr := string(f.Confidence)
		// Apply ANSI coloring if stdout is file or terminal
		switch f.Confidence {
		case models.ConfidenceConfirmed:
			confStr = "\x1b[32;1mCONFIRMED\x1b[0m"
		case models.ConfidenceDOMSink:
			confStr = "\x1b[33;1mDOM-SINK\x1b[0m"
		case models.ConfidenceBlockedByCSP:
			confStr = "\x1b[35mBLOCKED-CSP\x1b[0m"
		default:
			confStr = "\x1b[36mPOTENTIAL\x1b[0m"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", confStr, f.ParamName, f.Context, f.TargetURL, f.PayloadUsed)
	}
	return tw.Flush()
}

// WriteToFile writes output report to a specified filepath.
func WriteToFile(filepath string, findings []*models.Finding, format string, onlyConfirmed bool) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	w := NewWriter(file, format, onlyConfirmed)
	return w.WriteReport(findings)
}
