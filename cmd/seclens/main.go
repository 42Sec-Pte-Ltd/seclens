package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"seclens/internal/assessor"
	"seclens/internal/report"
)

const version = "0.1.0"

var (
	flagConcurrency = flag.Int("concurrency", 10, "Maximum number of domains to assess in parallel")
	flagFormat      = flag.String("format", "text", "Output format: text, json, jsonl")
	flagTimeout     = flag.Duration("timeout", 30*time.Second, "Overall timeout per domain")
	flagResolver    = flag.String("resolver", "cloudflare", "DoH resolver(s): cloudflare, google, quad9 (comma-separated for pool)")
	flagSMTP        = flag.Bool("smtp", false, "Perform optional deep SMTP/STARTTLS checks (port 25; often blocked)")
	flagFile        = flag.String("file", "", "Read domains from file (one per line)")
	flagStdin       = flag.Bool("stdin", false, "Read domains from stdin (one per line)")
	flagHelp        = flag.Bool("help", false, "Show help")
	flagVersion     = flag.Bool("version", false, "Show version")
)

func usage() {
	fmt.Fprintf(os.Stderr, `seclens - Email & Domain Security Assessor

Usage:
  seclens [assess] [flags] domain [domain...]
  seclens assess --file domains.txt
  cat domains.txt | seclens assess --stdin --format jsonl

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  seclens assess cloudflare.com
  seclens assess --format jsonl example.com google.com
  seclens assess --concurrency 64 --file domains.txt --format jsonl
  seclens assess --stdin --format json < domains.txt | jq -c .

Control set aligned with the SecLens Top-1M study
https://seclens.one/research/2026-07-email-security-top1m/
(SPF/DMARC/MTA-STS full policy validation, DNSSEC, DANE/TLSA, DKIM, TLS-RPT).
`)
}

func main() {
	flag.Usage = usage

	subcmd := ""
	if len(os.Args) > 1 {
		first := os.Args[1]
		if first == "assess" || first == "scan" {
			subcmd = first
			os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		}
	}

	flag.Parse()

	if *flagHelp {
		usage()
		os.Exit(0)
	}
	if *flagVersion {
		fmt.Printf("seclens %s\n", version)
		os.Exit(0)
	}

	assessor.SetDefaultResolver(*flagResolver)

	args := flag.Args()

	if subcmd == "assess" || subcmd == "scan" || (len(args) > 0 && (args[0] == "assess" || args[0] == "scan")) {
		if len(args) > 0 && (args[0] == "assess" || args[0] == "scan") {
			args = args[1:]
		}
	}

	if len(args) == 0 && *flagFile == "" && !*flagStdin {
		if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
			args = os.Args[1:]
		} else {
			usage()
			os.Exit(2)
		}
	}

	domains := args

	if *flagFile != "" {
		f, err := os.Open(*flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading --file %s: %v\n", *flagFile, err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				domains = append(domains, line)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "error reading --file %s: %v\n", *flagFile, err)
		}
		_ = f.Close()
	}

	if *flagStdin {
		stdin := bufio.NewScanner(os.Stdin)
		for stdin.Scan() {
			line := strings.TrimSpace(stdin.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				domains = append(domains, line)
			}
		}
		if err := stdin.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		}
	}

	if len(domains) == 0 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := assessor.AssessmentOpts{
		Timeout:  *flagTimeout,
		DoSMTP:   *flagSMTP,
		Resolver: *flagResolver,
	}

	filtered := make([]string, 0, len(domains))
	for _, d := range domains {
		dd := strings.ToLower(strings.TrimSpace(d))
		if dd != "" && assessor.IsValidDomainShape(dd) && assessor.IsAllowedDomain(dd) {
			filtered = append(filtered, dd)
		}
	}
	domains = filtered
	if len(domains) == 0 {
		fmt.Fprintf(os.Stderr, "no valid domains after input gating (shape/allowlist)\n")
		os.Exit(2)
	}

	fmtStr := strings.ToLower(*flagFormat)
	if fmtStr == "jsonl" && len(domains) > 1 {
		runJSONLStreaming(ctx, domains, opts, *flagConcurrency)
		return
	}

	var reports []report.Report
	if len(domains) == 1 {
		rep, err := assessor.Assess(ctx, domains[0], opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "assessment error: %v\n", err)
			os.Exit(1)
		}
		reports = []report.Report{rep}
	} else {
		reports = assessor.RunBulk(ctx, domains, opts, *flagConcurrency)
	}

	switch fmtStr {
	case "json":
		for _, r := range reports {
			fmt.Println(string(r.ToJSON()))
		}
	case "jsonl":
		for _, r := range reports {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
	default:
		for _, r := range reports {
			r.PrintText(os.Stdout)
		}
	}
}

func runJSONLStreaming(ctx context.Context, domains []string, opts assessor.AssessmentOpts, concurrency int) {
	if concurrency <= 0 {
		concurrency = 8
	}

	jobs := make(chan string, concurrency*2)
	results := make(chan report.Report, concurrency*2)

	var workWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workWg.Add(1)
		go func() {
			defer workWg.Done()
			for dom := range jobs {
				rep, err := assessor.Assess(ctx, dom, opts)
				if err != nil {
					if rep.Domain == "" {
						rep.Domain = dom
					}
					rep.Errors = append(rep.Errors, err.Error())
				}
				results <- rep
			}
		}()
	}

	var printWg sync.WaitGroup
	printWg.Add(1)
	go func() {
		defer printWg.Done()
		for rep := range results {
			b, _ := json.Marshal(rep)
			fmt.Println(string(b))
		}
	}()

	for _, d := range domains {
		jobs <- d
	}
	close(jobs)

	workWg.Wait()
	close(results)
	printWg.Wait()
}