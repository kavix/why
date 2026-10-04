package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kavix/why/internal/adapters"
	"github.com/kavix/why/internal/completion"
	"github.com/kavix/why/internal/engine"
	"github.com/kavix/why/internal/output"
)

var (
	Version   = "0.1.0"
	BuildDate = "2026-09-19"
)

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	var (
		deepFlag     bool
		explainFlag  bool
		jsonFlag     bool
		aiFlag       bool
		verboseFlag  bool
		versionFlag  bool
		timeoutSec   int
		portFlag     int
		identityFlag string
		methodFlag   string
		headersFlag  stringSlice
	)

	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.BoolVar(&deepFlag, "deep", false, "Perform deep/exhaustive diagnostic probes")
	fs.BoolVar(&explainFlag, "explain", false, "Show detailed causal explanation and remediation")
	fs.BoolVar(&jsonFlag, "json", false, "Emit structured machine-readable failure graph in JSON")
	fs.BoolVar(&aiFlag, "ai", false, "Use AI to explain failure causally and suggest fixes")
	fs.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	fs.BoolVar(&versionFlag, "version", false, "Print version information")
	fs.BoolVar(&versionFlag, "v", false, "Print version information")
	fs.IntVar(&timeoutSec, "timeout", 10, "Timeout for probes in seconds")
	fs.IntVar(&portFlag, "p", 0, "Port override")
	fs.StringVar(&identityFlag, "i", "", "SSH identity private key path")
	fs.StringVar(&methodFlag, "X", "GET", "HTTP request method")
	fs.Var(&headersFlag, "H", "HTTP header (format 'Header: value')")

	// Custom Usage banner
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `why — A Unix-native failure diagnosis and causal troubleshooting CLI.
"Don't just tell me that it failed. Tell me why."

Usage:
  why <protocol|command> <target> [flags]
  why <target> [flags]

Examples:
  why ssh user@server
  why ssh user@server -i ~/.ssh/deploy_key
  why curl https://api.example.com/health
  why dns example.com
  why tls example.com:443
  why tcp 10.0.0.1:5432

Advanced Flags:
  why ssh user@server --deep       # Exhaustive inspection of keys, resolvers, and handshake
  why curl https://site.com --ai   # AI-powered causal explanation and remediation
  why ssh user@server --json       # Machine-readable JSON failure graph for CI/CD

Options:
`)
		fs.PrintDefaults()
	}

	// Separate flags from positional arguments so flags can appear anywhere
	var flagArgs []string
	var posArgs []string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// If it's a flag that takes a value (not boolean) and value is next arg
			if (arg == "-i" || arg == "-p" || arg == "-X" || arg == "-H" || arg == "--timeout" || arg == "-timeout") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	if versionFlag {
		fmt.Printf("why version %s (%s)\n", Version, BuildDate)
		os.Exit(0)
	}

	if len(posArgs) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	if posArgs[0] == "completion" {
		completion.Completion(posArgs)
	}

	target := strings.Join(posArgs, " ")

	diagOpts := adapters.DiagnosticOptions{
		Deep:      deepFlag,
		Verbose:   verboseFlag,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Port:      portFlag,
		KeyPath:   identityFlag,
		Method:    methodFlag,
		Headers:   headersFlag,
		UserAgent: fmt.Sprintf("why/%s", Version),
	}

	runOpts := engine.RunOptions{
		DiagnosticOptions: diagOpts,
		Explain:           explainFlag,
		AI:                aiFlag,
		JSON:              jsonFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+5)*time.Second)
	defer cancel()

	eng := engine.New()
	diag, err := eng.Diagnose(ctx, target, runOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := output.Print(os.Stdout, diag, jsonFlag, explainFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
		os.Exit(1)
	}

	if diag.Status == "failed" {
		os.Exit(1)
	}
}
