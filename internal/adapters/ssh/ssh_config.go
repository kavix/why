package ssh

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// sshConfigPathFn is the OpenSSH user config path. Tests replace it.
var sshConfigPathFn = defaultSSHConfigPath

func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}

type sshConfigBlock struct {
	patterns     []string
	hostName     string
	user         string
	port         int
	identityFile string
}

func applySSHConfig(st *sshTarget, explicitUser, explicitPort bool) {
	if st == nil || st.Host == "" {
		return
	}
	cfgPath := sshConfigPathFn()
	if cfgPath == "" {
		return
	}
	blocks, err := parseSSHConfigFile(cfgPath)
	if err != nil || len(blocks) == 0 {
		return
	}
	alias := st.Host
	for _, b := range blocks {
		if !hostBlockMatches(b.patterns, alias) {
			continue
		}
		if b.hostName != "" && !st.fromConfig {
			st.alias = alias
			st.Host = expandHome(b.hostName)
			st.fromConfig = true
		}
		if b.user != "" && !explicitUser && !st.userFromConfig {
			st.User = b.user
			st.userFromConfig = true
		}
		if b.port > 0 && !explicitPort && !st.portFromConfig {
			st.Port = b.port
			st.portFromConfig = true
		}
		if b.identityFile != "" && st.KeyPath == "" {
			st.KeyPath = expandHome(b.identityFile)
		}
	}
}

func parseSSHConfigFile(pathName string) ([]sshConfigBlock, error) {
	f, err := os.Open(pathName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var blocks []sshConfigBlock
	var cur *sshConfigBlock
	inMatch := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		kw, rest := splitConfigKeyword(line)
		if kw == "" {
			continue
		}
		switch strings.ToLower(kw) {
		case "host":
			inMatch = false
			if cur != nil {
				blocks = append(blocks, *cur)
			}
			next := sshConfigBlock{patterns: strings.Fields(rest)}
			cur = &next
		case "match":
			inMatch = true
			if cur != nil {
				blocks = append(blocks, *cur)
				cur = nil
			}
		default:
			if inMatch || cur == nil {
				continue
			}
			switch strings.ToLower(kw) {
			case "hostname":
				if cur.hostName == "" && rest != "" {
					cur.hostName = rest
				}
			case "user":
				if cur.user == "" && rest != "" {
					cur.user = rest
				}
			case "port":
				if cur.port == 0 {
					if p, err := strconv.Atoi(rest); err == nil && p > 0 && p <= 65535 {
						cur.port = p
					}
				}
			case "identityfile":
				if cur.identityFile == "" && rest != "" {
					cur.identityFile = rest
				}
			}
		}
	}
	if cur != nil {
		blocks = append(blocks, *cur)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

func splitConfigKeyword(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(strings.TrimPrefix(line[i+1:], "="))
	}
	return line, ""
}

func hostBlockMatches(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return false
	}
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		pat := p
		if neg {
			pat = p[1:]
		}
		ok := hostPatternMatch(pat, name)
		if neg && ok {
			return false
		}
		if !neg && ok {
			matched = true
		}
	}
	return matched
}

func hostPatternMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return p
		}
		if p == "~" {
			return home
		}
		return filepath.Join(home, p[2:])
	}
	return p
}
