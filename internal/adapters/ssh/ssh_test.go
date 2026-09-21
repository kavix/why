package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSSHTarget_NoConfigFallsBack(t *testing.T) {
	dir := t.TempDir()
	sshConfigPathFn = func() string { return filepath.Join(dir, "missing-config") }
	t.Cleanup(func() { sshConfigPathFn = defaultSSHConfigPath })

	st, err := parseSSHTarget("ssh myserver")
	if err != nil {
		t.Fatalf("parseSSHTarget: %v", err)
	}
	if st.Host != "myserver" {
		t.Fatalf("host = %q, want alias unchanged", st.Host)
	}
	if st.fromConfig {
		t.Fatal("expected no config match")
	}
}

func TestParseSSHTarget_ResolvesHostAlias(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	body := "Host myserver\n" +
		"    HostName 192.168.1.150\n" +
		"    User ubuntu\n" +
		"    Port 2222\n" +
		"    IdentityFile ~/.ssh/id_ed25519_custom\n"
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	sshConfigPathFn = func() string { return cfg }
	t.Cleanup(func() { sshConfigPathFn = defaultSSHConfigPath })

	st, err := parseSSHTarget("ssh myserver")
	if err != nil {
		t.Fatalf("parseSSHTarget: %v", err)
	}
	if st.Host != "192.168.1.150" {
		t.Errorf("Host = %q, want 192.168.1.150", st.Host)
	}
	if st.User != "ubuntu" {
		t.Errorf("User = %q, want ubuntu", st.User)
	}
	if st.Port != 2222 {
		t.Errorf("Port = %d, want 2222", st.Port)
	}
	if !st.fromConfig {
		t.Error("fromConfig = false")
	}
	if st.alias != "myserver" {
		t.Errorf("alias = %q, want myserver", st.alias)
	}
	if !stringsHasSuffix(st.KeyPath, filepath.Join(".ssh", "id_ed25519_custom")) {
		t.Errorf("KeyPath = %q, want expanded IdentityFile", st.KeyPath)
	}
}

func TestParseSSHTarget_ExplicitUserAndPortWin(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	body := "Host myserver\n    HostName 10.0.0.9\n    User ubuntu\n    Port 2222\n"
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	sshConfigPathFn = func() string { return cfg }
	t.Cleanup(func() { sshConfigPathFn = defaultSSHConfigPath })

	st, err := parseSSHTarget("deploy@myserver:2200")
	if err != nil {
		t.Fatalf("parseSSHTarget: %v", err)
	}
	if st.Host != "10.0.0.9" {
		t.Errorf("Host = %q, want 10.0.0.9", st.Host)
	}
	if st.User != "deploy" {
		t.Errorf("User = %q, want deploy", st.User)
	}
	if st.Port != 2200 {
		t.Errorf("Port = %d, want 2200", st.Port)
	}
}

func TestHostBlockMatches_Negation(t *testing.T) {
	if hostBlockMatches([]string{"*.lan", "!skip.lan"}, "app.lan") != true {
		t.Fatal("app.lan should match *.lan")
	}
	if hostBlockMatches([]string{"*.lan", "!skip.lan"}, "skip.lan") != false {
		t.Fatal("skip.lan should be negated")
	}
}

func TestParseSSHConfigFile_IgnoresMatchBlocks(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	body := "Match host foo\n    User nobody\nHost bar\n    HostName 127.0.0.1\n    User me\n"
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	blocks, err := parseSSHConfigFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1 Host block", len(blocks))
	}
	if blocks[0].user != "me" || blocks[0].hostName != "127.0.0.1" {
		t.Fatalf("unexpected block: %+v", blocks[0])
	}
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
