package ssh

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kavix/why/internal/adapters"
	"github.com/kavix/why/internal/model"
	gossh "golang.org/x/crypto/ssh"
)

type SSHAdapter struct{}

func New() *SSHAdapter {
	return &SSHAdapter{}
}

func (a *SSHAdapter) Name() string     { return "ssh" }
func (a *SSHAdapter) Protocol() string { return "ssh" }

func (a *SSHAdapter) CanHandle(target string) bool {
	clean := strings.TrimSpace(target)
	if strings.HasPrefix(clean, "ssh ") {
		return true
	}
	if strings.HasPrefix(clean, "ssh://") {
		return true
	}
	// user@host syntax
	if strings.Contains(clean, "@") && !strings.Contains(clean, "://") && !strings.Contains(clean, " ") {
		return true
	}
	return false
}

type sshTarget struct {
	User           string
	Host           string
	Port           int
	KeyPath        string
	alias          string
	fromConfig     bool
	userFromConfig bool
	portFromConfig bool
}

func parseSSHTarget(target string) (*sshTarget, error) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "ssh ")
	target = strings.TrimPrefix(target, "ssh://")

	currentUser := "root"
	if u, err := user.Current(); err == nil && u.Username != "" {
		currentUser = u.Username
	}

	st := &sshTarget{
		User: currentUser,
		Port: 22,
	}

	explicitUser := false
	explicitPort := false

	// Extract user if present (user@host)
	if idx := strings.Index(target, "@"); idx != -1 {
		st.User = target[:idx]
		target = target[idx+1:]
		explicitUser = true
	}

	// Extract port if present (host:port)
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			st.Host = h
			if portInt, err := strconv.Atoi(p); err == nil {
				st.Port = portInt
				explicitPort = true
			}
			applySSHConfig(st, explicitUser, explicitPort)
			return st, nil
		}
	}

	// Clean trailing slash
	st.Host = strings.TrimSuffix(target, "/")
	applySSHConfig(st, explicitUser, explicitPort)
	return st, nil
}

func (a *SSHAdapter) Diagnose(ctx context.Context, target string, opts adapters.DiagnosticOptions) (*model.Diagnostic, error) {
	parsed, err := parseSSHTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid SSH target: %w", err)
	}

	if opts.Port > 0 {
		parsed.Port = opts.Port
	}
	if opts.KeyPath != "" {
		parsed.KeyPath = opts.KeyPath
	}

	diag := &model.Diagnostic{
		Target:    fmt.Sprintf("ssh://%s@%s:%d", parsed.User, parsed.Host, parsed.Port),
		Protocol:  "ssh",
		Timestamp: time.Now(),
		Status:    "passed",
		Metadata: map[string]interface{}{
			"user": parsed.User,
			"host": parsed.Host,
			"port": parsed.Port,
		},
	}
	if parsed.fromConfig {
		diag.Metadata["ssh_config_alias"] = true
		diag.Metadata["resolved_hostname"] = parsed.Host
		if parsed.alias != "" {
			diag.Metadata["alias"] = parsed.alias
		}
	}

	startTotal := time.Now()

	// 1. Local environment & Key check
	c1Start := time.Now()
	keysFound, keyEvidence := findLocalSSHKeys(parsed.KeyPath)
	if parsed.fromConfig {
		keyEvidence["ssh_config_alias"] = true
		keyEvidence["resolved_hostname"] = parsed.Host
		if parsed.alias != "" {
			keyEvidence["alias"] = parsed.alias
		}
	}
	diag.Checks = append(diag.Checks, model.Check{
		Name:        "Local SSH Keys & Config",
		Stage:       "local_env",
		Status:      model.StatusPassed,
		Duration:    time.Since(c1Start),
		DurationStr: time.Since(c1Start).String(),
		Summary:     fmt.Sprintf("Found %d local private key(s)", len(keysFound)),
		Evidence:    keyEvidence,
	})

	// 2. DNS Resolution
	c2Start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Host)
	c2Dur := time.Since(c2Start)
	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "dns"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "DNS Resolution",
			Stage:       "dns",
			Status:      model.StatusFailed,
			Duration:    c2Dur,
			DurationStr: c2Dur.String(),
			Error:       err.Error(),
			Evidence:    map[string]interface{}{"host": parsed.Host},
		})
		diag.Failure = &model.Failure{
			Stage:  "dns",
			Check:  "DNS Resolution",
			Reason: fmt.Sprintf("Failed to resolve SSH host %q: %v", parsed.Host, err),
			Evidence: map[string]interface{}{
				"host": parsed.Host,
				"err":  err.Error(),
			},
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	resolvedIP := ips[0].IP.String()
	diag.Checks = append(diag.Checks, model.Check{
		Name:        "DNS Resolution",
		Stage:       "dns",
		Status:      model.StatusPassed,
		Duration:    c2Dur,
		DurationStr: c2Dur.String(),
		Summary:     fmt.Sprintf("Resolved %s -> %s", parsed.Host, resolvedIP),
		Evidence: map[string]interface{}{
			"host": parsed.Host,
			"ip":   resolvedIP,
		},
	})

	// 3. TCP Connect to port (default 22)
	c3Start := time.Now()
	sshAddr := net.JoinHostPort(resolvedIP, strconv.Itoa(parsed.Port))
	dialer := net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", sshAddr)
	c3Dur := time.Since(c3Start)

	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "tcp"
		errStr := err.Error()
		evidence := map[string]interface{}{
			"host":        parsed.Host,
			"ip":          resolvedIP,
			"port":        parsed.Port,
			"destination": sshAddr,
			"raw_error":   errStr,
		}

		reason := fmt.Sprintf("TCP connect to %s failed", sshAddr)
		if strings.Contains(errStr, "connection refused") {
			reason = fmt.Sprintf("Connection refused on port %d (SSHD daemon is not running or port is closed)", parsed.Port)
			evidence["state"] = "ECONNREFUSED"
		} else if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
			reason = fmt.Sprintf("Connection timed out on port %d (Firewall/Security Group dropping SYN packets)", parsed.Port)
			evidence["state"] = "ETIMEDOUT"
		}

		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("TCP Connect :%d", parsed.Port),
			Stage:       "tcp",
			Status:      model.StatusFailed,
			Duration:    c3Dur,
			DurationStr: c3Dur.String(),
			Error:       errStr,
			Evidence:    evidence,
		})

		diag.Failure = &model.Failure{
			Stage:    "tcp",
			Check:    fmt.Sprintf("TCP Connect :%d", parsed.Port),
			Reason:   reason,
			Evidence: evidence,
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}
	defer rawConn.Close()

	diag.Checks = append(diag.Checks, model.Check{
		Name:        fmt.Sprintf("TCP Connect :%d", parsed.Port),
		Stage:       "tcp",
		Status:      model.StatusPassed,
		Duration:    c3Dur,
		DurationStr: c3Dur.String(),
		Summary:     fmt.Sprintf("Connected in %v", c3Dur),
		Evidence: map[string]interface{}{
			"rtt": c3Dur.String(),
		},
	})

	// 4. SSH Protocol Handshake & Banner Exchange
	c4Start := time.Now()
	_ = rawConn.SetDeadline(time.Now().Add(4 * time.Second))

	// Read server banner line: e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
	reader := bufio.NewReader(rawConn)
	serverBanner, err := reader.ReadString('\n')
	c4Dur := time.Since(c4Start)

	if err != nil || !strings.HasPrefix(serverBanner, "SSH-") {
		diag.Status = "failed"
		diag.FailedAt = "ssh_handshake"
		errSummary := "Server did not reply with valid SSH-2.0 banner"
		if err != nil {
			errSummary = err.Error()
		}

		evidence := map[string]interface{}{
			"raw_banner": serverBanner,
			"error":      errSummary,
		}

		diag.Checks = append(diag.Checks, model.Check{
			Name:        "SSH Banner Exchange",
			Stage:       "ssh_handshake",
			Status:      model.StatusFailed,
			Duration:    c4Dur,
			DurationStr: c4Dur.String(),
			Error:       errSummary,
			Evidence:    evidence,
		})

		diag.Failure = &model.Failure{
			Stage:    "ssh_handshake",
			Check:    "SSH Banner Exchange",
			Reason:   "Target responded to TCP connection but failed to emit SSH identification banner (non-SSH service on port?)",
			Evidence: evidence,
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	serverBanner = strings.TrimSpace(serverBanner)
	diag.Checks = append(diag.Checks, model.Check{
		Name:        "SSH Banner Exchange",
		Stage:       "ssh_handshake",
		Status:      model.StatusPassed,
		Duration:    c4Dur,
		DurationStr: c4Dur.String(),
		Summary:     serverBanner,
		Evidence: map[string]interface{}{
			"banner": serverBanner,
		},
	})

	// 5. Key Exchange (KEX) & Host Key Verification Probe
	// Re-establish dedicated connection for gossh client handshake to extract host key and supported auth methods
	c5Start := time.Now()
	var serverHostKey gossh.PublicKey
	var hostKeyAlgo string

	hostKeyCallback := func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		serverHostKey = key
		hostKeyAlgo = key.Type()
		return nil
	}

	var authMethods []gossh.AuthMethod
	attemptedKeys := []string{}

	// Load local keys
	for _, kpath := range keysFound {
		keyBytes, err := os.ReadFile(kpath)
		if err == nil {
			signer, err := gossh.ParsePrivateKey(keyBytes)
			if err == nil {
				authMethods = append(authMethods, gossh.PublicKeys(signer))
				attemptedKeys = append(attemptedKeys, kpath)
			}
		}
	}

	// If no valid local keys, provide a dummy pubkey to query supported auth methods
	if len(authMethods) == 0 {
		authMethods = append(authMethods, gossh.Password("dummy-why-test-probe"))
	}

	sshConfig := &gossh.ClientConfig{
		User:            parsed.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         4 * time.Second,
	}

	sshConn, err := gossh.Dial("tcp", sshAddr, sshConfig)
	c5Dur := time.Since(c5Start)

	var hostKeyFingerprint string
	if serverHostKey != nil {
		sha := sha256.Sum256(serverHostKey.Marshal())
		hostKeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sha[:])
	}

	// 5. Host Key Check
	if serverHostKey != nil {
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "Host Key & KEX Negotiation",
			Stage:       "host_key",
			Status:      model.StatusPassed,
			Duration:    c5Dur / 2,
			DurationStr: (c5Dur / 2).String(),
			Summary:     fmt.Sprintf("%s (%s)", hostKeyAlgo, hostKeyFingerprint),
			Evidence: map[string]interface{}{
				"algorithm":   hostKeyAlgo,
				"fingerprint": hostKeyFingerprint,
			},
		})
	}

	// 6. Authentication Stage
	c6Start := time.Now()
	if err != nil {
		// Gossh handshake failed. Analyze if it's an authentication rejection or something else
		errStr := err.Error()

		if strings.Contains(errStr, "ssh: unable to authenticate") {
			// Extract methods accepted by server
			// Example error: "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"
			// Or: "unable to authenticate, attempted methods [publickey], accepted methods [publickey password]"
			diag.Status = "failed"
			diag.FailedAt = "authentication"

			acceptedMethods := parseAcceptedAuthMethods(errStr)
			if len(acceptedMethods) == 0 {
				acceptedMethods = []string{"publickey", "password", "keyboard-interactive"}
			}

			authEvidence := map[string]interface{}{
				"username":         parsed.User,
				"methods_offered":  []string{"publickey"},
				"methods_accepted": acceptedMethods,
				"keys_attempted":   attemptedKeys,
				"raw_error":        errStr,
			}

			diag.Checks = append(diag.Checks, model.Check{
				Name:        "User Authentication",
				Stage:       "authentication",
				Status:      model.StatusFailed,
				Duration:    time.Since(c6Start),
				DurationStr: time.Since(c6Start).String(),
				Error:       "Server rejected client authentication credentials",
				Evidence:    authEvidence,
			})

			diag.Failure = &model.Failure{
				Stage:    "authentication",
				Check:    "User Authentication",
				Reason:   fmt.Sprintf("Server rejected authentication for user %q", parsed.User),
				Evidence: authEvidence,
			}

			diag.TotalElapsed = time.Since(startTotal).String()
			return diag, nil
		}

		// Other handshake failure (host key mismatch, KEX failure)
		diag.Status = "failed"
		diag.FailedAt = "ssh_kex"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "KEX / Protocol Handshake",
			Stage:       "ssh_kex",
			Status:      model.StatusFailed,
			Duration:    c5Dur,
			DurationStr: c5Dur.String(),
			Error:       errStr,
		})

		diag.Failure = &model.Failure{
			Stage:  "ssh_kex",
			Check:  "KEX / Protocol Handshake",
			Reason: fmt.Sprintf("SSH protocol handshake failed: %v", err),
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	// If we got here, SSH connection actually succeeded!
	defer sshConn.Close()

	diag.Checks = append(diag.Checks, model.Check{
		Name:        "User Authentication",
		Stage:       "authentication",
		Status:      model.StatusPassed,
		Duration:    time.Since(c6Start),
		DurationStr: time.Since(c6Start).String(),
		Summary:     fmt.Sprintf("Authenticated successfully as %s", parsed.User),
		Evidence: map[string]interface{}{
			"username": parsed.User,
			"method":   "publickey",
		},
	})

	diag.TotalElapsed = time.Since(startTotal).String()
	return diag, nil
}

func findLocalSSHKeys(customKey string) ([]string, map[string]interface{}) {
	var keys []string
	evidence := make(map[string]interface{})

	if customKey != "" {
		if _, err := os.Stat(customKey); err == nil {
			keys = append(keys, customKey)
			evidence["custom_key"] = customKey
			return keys, evidence
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return keys, evidence
	}

	sshDir := filepath.Join(home, ".ssh")
	standardNames := []string{
		"id_ed25519",
		"id_rsa",
		"id_ecdsa",
		"id_dsa",
	}

	foundList := []string{}
	for _, name := range standardNames {
		keyPath := filepath.Join(sshDir, name)
		if fi, err := os.Stat(keyPath); err == nil && !fi.IsDir() {
			keys = append(keys, keyPath)
			foundList = append(foundList, keyPath)
			// Check file permissions (should be 0600)
			perm := fi.Mode().Perm()
			if perm != 0600 && perm != 0400 {
				evidence[name+"_perms_warning"] = fmt.Sprintf("Permissions are %04o (should be 0600)", perm)
			}
		}
	}

	evidence["ssh_dir"] = sshDir
	evidence["local_keys"] = foundList
	return keys, evidence
}

func parseAcceptedAuthMethods(errStr string) []string {
	var methods []string
	// Check keywords
	for _, m := range []string{"publickey", "password", "keyboard-interactive", "gssapi-with-mic", "hostbased"} {
		if strings.Contains(errStr, m) {
			methods = append(methods, m)
		}
	}
	return methods
}
