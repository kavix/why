package completion

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
)

//go:embed bash-completions.bash
var bashCompletion string

//go:embed zsh-completions.zsh
var zshCompletion string

//go:embed fish-completions.fish
var fishCompletion string

type entry struct {
	name        string
	description string
}

var subCommands = []entry{
	{"curl", "Diagnose an HTTP request"},
	{"dns", "Diagnose DNS resolution"},
	{"http", "Diagnose HTTP/HTTPS connection"},
	{"tcp", "Diagnose a TCP connection"},
	{"ssh", "Diagnose an SSH connection"},
	{"tls", "Diagnose a tls connection"},
	{"completion", "Print completions shell script"},
}

var flags = []entry{
	{"--deep", "Run thorough diagnostic probes"},
	{"--ai", "Explain failures with AI"},
	{"--explain", "Show causes and suggested fixes"},
	{"--json", "Output results as JSON"},
	{"--verbose", "Show detailed output"},
	{"--version", "Print version information"},
	{"--timeout", "Set probe timeout in seconds"},
	{"-v", "Print version information"},
	{"-i", "Set the SSH private key path"},
	{"-p", "Override the port"},
	{"-X", "Set the HTTP request method"},
	{"-H", "Add an HTTP request header"},
}

func names(entries []entry) []string {
	result := make([]string, 0, len(entries))
	for _, item := range entries {
		result = append(result, item.name)
	}
	return result
}

func formatEntries(entries []entry, shell string) (string, bool) {
	switch shell {
	case "bash":
		return strings.Join(names(entries), " ") + "\n", true
	case "zsh", "fish":
		separator := ":"
		if shell == "fish" {
			separator = "\t"
		}

		var output strings.Builder
		for _, item := range entries {
			fmt.Fprintf(&output, "%s%s%s\n", item.name, separator, item.description)
		}
		return output.String(), true
	default:
		return "", false
	}
}

func Completion(args []string) {
	if len(args) == 0 {
		return
	}

	action := "bash"
	if len(args) > 1 {
		action = args[1]
	}

	var output string
	switch action {
	case "bash", "zsh", "fish":
		output = Complete(action)
	case "list-commands", "list-flags":
		shell := "bash"
		if len(args) > 2 {
			shell = args[2]
		}

		entries := subCommands
		if action == "list-flags" {
			entries = flags
		}

		var ok bool
		output, ok = formatEntries(entries, shell)
		if !ok {
			fmt.Fprint(os.Stdout, "Invalid or unsupported shell")
			os.Exit(1)
		}
	default:
		return
	}

	fmt.Fprint(os.Stdout, output)
	os.Exit(0)
}

func CompleteSubCommands() []string {
	return names(subCommands)
}

func CompleteFlags() []string {
	return names(flags)
}

func Complete(shell string) string {
	switch shell {
	case "bash":
		return bashCompletion
	case "zsh":
		return zshCompletion
	case "fish":
		return fishCompletion
	default:
		return "echo Invalid or unsupported shell completion is sourced for why completions"
	}
}
