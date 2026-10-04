package completion

import (
	"slices"
	"testing"
)

func TestCompleteSelectShell(t *testing.T) {
	list := [...]string{"bash", "zsh", "fish"}

	for _, shell := range list {
		completionScript := Complete(shell)
		if len(completionScript) == 0 {
			t.Errorf("Error in %s completion script", shell)
		}
	}
}

func TestListCommands(t *testing.T) {
	subCommands := [...]string{"ssh", "curl", "tcp", "tls", "dns", "http", "completion"}

	got := CompleteSubCommands()

	for _, cmd := range subCommands {
		if !slices.Contains(got, cmd) {
			t.Errorf("Error: subcommand %s is missing in list-commands", cmd)
		}
	}
}

func TestListFlags(t *testing.T) {
	flags := [...]string{"-i", "-p", "-X", "-v", "-H", "--ai", "--deep", "--explain", "--timeout", "--json", "--version", "--verbose"}

	got := CompleteFlags()

	for _, flag := range flags {
		if !slices.Contains(got, flag) {
			t.Errorf("Error: flag %s is missing in list-flags", flag)
		}
	}
}

func TestFormatEntries(t *testing.T) {
	entries := []entry{
		{name: "dns", description: "Diagnose DNS resolution"},
		{name: "--timeout", description: "Set probe timeout in seconds"},
	}

	tests := []struct {
		name      string
		shell     string
		want      string
		supported bool
	}{
		{name: "bash", shell: "bash", want: "dns --timeout\n", supported: true},
		{name: "zsh", shell: "zsh", want: "dns:Diagnose DNS resolution\n--timeout:Set probe timeout in seconds\n", supported: true},
		{name: "fish", shell: "fish", want: "dns\tDiagnose DNS resolution\n--timeout\tSet probe timeout in seconds\n", supported: true},
		{name: "unsupported", shell: "unknown", want: "", supported: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, supported := formatEntries(entries, tt.shell)
			if supported != tt.supported || got != tt.want {
				t.Errorf("formatEntries(%q) = (%q, %t), want (%q, %t)", tt.shell, got, supported, tt.want, tt.supported)
			}
		})
	}
}

func TestCompletionEntriesHaveDescriptions(t *testing.T) {
	groups := []struct {
		name    string
		entries []entry
	}{
		{name: "commands", entries: subCommands},
		{name: "flags", entries: flags},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			seen := make(map[string]bool)
			for _, item := range group.entries {
				if item.name == "" || item.description == "" {
					t.Errorf("entry has an empty name or description: %+v", item)
				}
				if seen[item.name] {
					t.Errorf("duplicate completion name %q", item.name)
				}
				seen[item.name] = true
			}
		})
	}
}
