package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/youwannahackme/XSSReaper/internal/browser"
	"github.com/youwannahackme/XSSReaper/internal/output"
	"github.com/youwannahackme/XSSReaper/internal/payloads"
	"github.com/youwannahackme/XSSReaper/internal/scanner"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func printProfessionalHelp() {
	banner := `
  ` + "\x1b[31;1m" + `
  ██╗  ██╗███████╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
  ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
   ╚███╔╝ ███████╗███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
   ██╔██╗ ╚════██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██╔╝ ██╗███████║███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝` + "\x1b[0m" + `
                    ` + "\x1b[33;1m" + `XSSReaper - Headless & DOM XSS Scanner` + "\x1b[0m" + `
`
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintln(os.Stderr, "========================================================================================")
	fmt.Fprintln(os.Stderr, "  \x1b[1mAuthor:\x1b[0m whoami_404")
	fmt.Fprintln(os.Stderr, "  \x1b[1mGitHub:\x1b[0m https://github.com/youwannahackme/XSSReaper")
	fmt.Fprintln(os.Stderr, "========================================================================================")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "  XSSReaper [OPTIONS]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "TARGET SPECIFICATION:")
	fmt.Fprintln(os.Stderr, "  -u <url>                 Single target URL to scan (GET parameters will be fuzzed)")
	fmt.Fprintln(os.Stderr, "  -l <file>                File containing a list of target URLs (one per line)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "DETECTION & CONFIRMATION TIERS:")
	fmt.Fprintln(os.Stderr, "  -confirm                 Enable Tier 3 headless browser execution confirmation (chromedp)")
	fmt.Fprintln(os.Stderr, "  -dom                     Enable Tier 2 client-side DOM-sink instrumentation (requires -confirm)")
	fmt.Fprintln(os.Stderr, "  -all-payloads            Test all embedded 2,800+ payloads during Tier 3 confirmation (brute-force)")
	fmt.Fprintln(os.Stderr, "  -p <file>                Custom payload wordlist file (defaults to embedded polyglot & XSS lists)")
	fmt.Fprintln(os.Stderr, "  -oob <url>               Optional out-of-band callback URL for blind/OOB detection")
	fmt.Fprintln(os.Stderr, "  -respect-csp             Downgrade findings blocked by target Content-Security-Policy")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "PERFORMANCE & TUNING:")
	fmt.Fprintln(os.Stderr, "  -c <int>                 Per-host adaptive concurrency limit (default: 25)")
	fmt.Fprintln(os.Stderr, "  -timeout <duration>      Per-request HTTP timeout duration (default: 10s)")
	fmt.Fprintln(os.Stderr, "  -H <header>              Custom HTTP header, repeatable (e.g., -H \"Authorization: Bearer x\")")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OUTPUT & REPORTING:")
	fmt.Fprintln(os.Stderr, "  -o <file>                Save results to an output file")
	fmt.Fprintln(os.Stderr, "  -format <string>         Output report format: table or json (default: table)")
	fmt.Fprintln(os.Stderr, "  -only-confirmed          Suppress unconfirmed Potential/DOM-Sink results")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "INSTALL DIRECT:")
	fmt.Fprintln(os.Stderr, "  go install -v github.com/youwannahackme/XSSReaper@latest")
	fmt.Fprintln(os.Stderr, "========================================================================================")
}

func main() {
	flag.Usage = printProfessionalHelp
	var (
		urlFlag         string
		listFile        string
		payloadFile     string
		concurrencyFlag int
		timeoutFlag     time.Duration
		headersFlag     stringSliceFlag
		confirmFlag     bool
		domFlag         bool
		allPayloadsFlag bool
		oobFlag         string
		respectCSPFlag  bool
		outFile         string
		formatFlag      string
		onlyConfirmed   bool
	)

	flag.StringVar(&urlFlag, "u", "", "Single target URL")
	flag.StringVar(&listFile, "l", "", "File of target URLs, one per line")
	flag.StringVar(&payloadFile, "p", "", "Custom payload list file (one per line)")
	flag.IntVar(&concurrencyFlag, "c", 25, "Per-host throttled concurrency limit")
	flag.DurationVar(&timeoutFlag, "timeout", 10*time.Second, "Per-request HTTP timeout")
	flag.Var(&headersFlag, "H", "Repeatable custom HTTP header (e.g., -H 'Authorization: Bearer x')")
	flag.BoolVar(&confirmFlag, "confirm", false, "Enable Tier 3 headless confirmation (chromedp)")
	flag.BoolVar(&domFlag, "dom", false, "Enable Tier 2 DOM-sink instrumentation (requires -confirm)")
	flag.BoolVar(&allPayloadsFlag, "all-payloads", false, "Test all embedded/custom wordlist payloads in Tier 3 (brute-force mode)")
	flag.StringVar(&oobFlag, "oob", "", "Optional out-of-band callback base URL")
	flag.BoolVar(&respectCSPFlag, "respect-csp", false, "Downgrade findings blocked by target Content-Security-Policy")
	flag.StringVar(&outFile, "o", "", "Output file path")
	flag.StringVar(&formatFlag, "format", "table", "Output format: table or json")
	flag.BoolVar(&onlyConfirmed, "only-confirmed", false, "Suppress Potential/DOM-Sink results")

	flag.Parse()

	// Setup structured logging
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if domFlag && !confirmFlag {
		slog.Error("Flag -dom requires -confirm to be set")
		os.Exit(1)
	}

	if confirmFlag || domFlag {
		if path := browser.FindExecPath(); path == "" {
			slog.Error("Headless browser execution requires Google Chrome, Chromium, or Microsoft Edge to be installed. Please install a browser or specify its path using the CHROME_PATH environment variable.")
			os.Exit(1)
		}
	}

	var targetURLs []string
	if urlFlag != "" {
		targetURLs = append(targetURLs, urlFlag)
	}
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			slog.Error("Failed to open URL list file", slog.String("file", listFile), slog.Any("error", err))
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targetURLs = append(targetURLs, line)
			}
		}
		if err := scanner.Err(); err != nil {
			slog.Error("Error reading URL list file", slog.String("file", listFile), slog.Any("error", err))
			os.Exit(1)
		}
		f.Close()
	}

	if len(targetURLs) == 0 {
		slog.Error("No target URLs specified. Provide -u <url> or -l <file>")
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var payloadsList []string
	if payloadFile != "" {
		f, err := os.Open(payloadFile)
		if err != nil {
			slog.Error("Failed to open custom payload list file", slog.String("file", payloadFile), slog.Any("error", err))
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				payloadsList = append(payloadsList, line)
			}
		}
		if err := scanner.Err(); err != nil {
			slog.Error("Error reading payload list file", slog.String("file", payloadFile), slog.Any("error", err))
			os.Exit(1)
		}
		f.Close()
	} else {
		payloadsList = payloads.GetDefaultPayloadList()
	}

	cfg := scanner.Config{
		Concurrency:   concurrencyFlag,
		Timeout:       timeoutFlag,
		Headers:       headersFlag,
		Confirm:       confirmFlag,
		DOM:           domFlag,
		AllPayloads:   allPayloadsFlag,
		OOBURL:        oobFlag,
		RespectCSP:    respectCSPFlag,
		OnlyConfirmed: onlyConfirmed,
		Payloads:      payloadsList,
	}

	engine := scanner.NewEngine(cfg)

	// Print red title banner in real usage
	titleBanner := "\x1b[31;1m" + `
  ██╗  ██╗███████╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
  ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
   ╚███╔╝ ███████╗███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
   ██╔██╗ ╚════██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██╔╝ ██╗███████║███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
` + "\x1b[0m"
	fmt.Fprint(os.Stderr, titleBanner)

	slog.Info("Starting XSSReaper scan",
		slog.Int("targets", len(targetURLs)),
		slog.Int("concurrency", cfg.Concurrency),
		slog.Bool("tier2_dom", cfg.DOM),
		slog.Bool("tier3_confirm", cfg.Confirm),
	)

	findings, err := engine.ScanTargets(ctx, targetURLs)
	if err != nil {
		slog.Error("Scan failed", slog.Any("error", err))
		os.Exit(1)
	}

	writer := output.NewWriter(os.Stdout, formatFlag, onlyConfirmed)
	if err := writer.WriteReport(findings); err != nil {
		slog.Error("Failed writing output report", slog.Any("error", err))
		os.Exit(1)
	}

	if outFile != "" {
		if err := output.WriteToFile(outFile, findings, formatFlag, onlyConfirmed); err != nil {
			slog.Error("Failed writing output to file", slog.String("file", outFile), slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("Report written to file", slog.String("file", outFile))
	}
}
