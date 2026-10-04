# why

<div align="center">

> **"Don't just tell me that it failed. Tell me why."**

A Unix-native failure diagnosis and causal troubleshooting CLI with optional AI analysis.

[![Go Version](https://img.shields.io/github/go-mod/go-version/kavix/why)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue.svg)](CONTRIBUTING.md)

</div>

---

## What is `why`?

When a network connection, deployment, or command breaks, standard tools only tell you **that** it failed:

```console
$ ssh user@server
Permission denied (publickey).

$ curl https://api.internal/v1/resource
curl: (22) The requested URL returned error: 403
```

You are left manually checking DNS, verifying ports with `nc`, inspecting certificate chains with `openssl`, checking SSH permissions, and reading obscure logs.

**`why` replaces this guesswork with causal diagnosis.** It treats troubleshooting as a causal graph problem: it probes each stage in the execution path, captures structured evidence, isolates the exact point of failure, and tells you what went wrong and how to fix it.

```console
$ why ssh deploy@remote.server

✗ SSH FAILED  (failed at authentication in 184ms)

✓ Local SSH Keys & Config      Found 2 local private key(s)
✓ DNS Resolution               Resolved remote.server -> 93.184.216.34
✓ TCP Connect :22              Connected in 42ms
✓ SSH Banner Exchange          SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
✓ Host Key & KEX Negotiation   ssh-ed25519 (SHA256:7mP0V...vX1)
✗ User Authentication          Server rejected client authentication credentials

Cause
────────────────────────────────────────
The SSH server rejected your credentials for user "deploy".

client offered:
  ~/.ssh/id_ed25519
server accepts:
  publickey, keyboard-interactive

Likely causes & fixes:
  • Install your public key on the server: ssh-copy-id -p 22 deploy@remote.server
  • Verify your key permissions locally: chmod 600 ~/.ssh/id_* && chmod 700 ~/.ssh
  • Ensure remote ~/.ssh/authorized_keys exists and has 0600 permissions
  • If connecting with a specific key, run: why ssh -i ~/.ssh/your_key deploy@remote.server

Try:
  why ssh deploy@remote.server --deep
  why ssh deploy@remote.server --ai
  why ssh deploy@remote.server --json
```

---

## Key Features

- **Protocol-Aware Diagnostic Pipeline**: First-class multi-stage probes for **SSH**, **HTTP / curl**, **DNS**, **TLS/SSL**, and **TCP**.
- **Separation of Diagnostics & Explanation**: Probes emit machine-readable facts; an independent causal engine produces human explanations.
- **`--json` for CI/CD & Automation**: Emits a complete structured failure graph with timings, dependencies, and hypotheses for automation.
- **`--deep` Mode**: Runs exhaustive secondary checks (alternate public resolvers, multiple cipher suites, certificate chains).
- **Optional AI Explanation (`--ai`)**: Seamlessly enriches causal reasoning with local offline models (**Ollama**) or cloud APIs (**Gemini**, **OpenAI**, **Claude**).
- **Single Static Binary**: Written in Go with zero external runtime dependencies. Fast, offline-first, and Unix-native.

---

## Quick Start

### Installation

#### Using Go:
```bash
go install github.com/kavix/why/cmd/why@latest
```

#### From Source:
```bash
git clone https://github.com/kavix/why.git
cd why
make build
sudo cp bin/why /usr/local/bin/
```

---

### Autocompletion

`why` supports Bash, Zsh, and Fish completion. Make sure `why` is on your `PATH`, then enable it for your shell:

#### Bash (`~/.bashrc`)
```bash
source <(why completion bash)
```

#### Zsh (`~/.zshrc`, after `compinit`)
```zsh
source <(why completion zsh)
```

#### Fish
```fish
mkdir -p ~/.config/fish/completions
why completion fish > ~/.config/fish/completions/why.fish
```

## Usage Examples

### 1. Diagnosing SSH Failures
```bash
why ssh user@myhost.com
why ssh user@myhost.com:2222
why ssh -i ~/.ssh/custom_key user@myhost.com
```

### 2. Diagnosing HTTP & Web Endpoints
```bash
why curl https://api.example.com/v1/health
why http https://broken-site.internal:8443
why curl https://api.example.com/checkout -X POST -H "Authorization: Bearer test"
```

### 3. Diagnosing DNS Issues
```bash
why dns broken-domain.com
why dns internal.service.local --deep
```

### 4. Diagnosing TLS & Certificate Problems
```bash
why tls expired.badssl.com:443
why tls self-signed.badssl.com:443
```

### 5. Diagnosing Raw TCP Ports
```bash
why tcp 10.0.0.1:5432
why tcp 192.168.1.50:8080
```

---

## Flags & Options

| Flag | Description |
|------|-------------|
| `--explain` | Displays an expanded causal breakdown and troubleshooting playbook |
| `--deep` | Executes deep probe extensions (alternate DNS resolvers, cipher audits) |
| `--json` | Outputs the structured failure graph as formatted JSON |
| `--ai` | Generates AI-assisted root cause analysis & remediation commands |
| `--timeout <sec>` | Probe execution timeout (default: 10s) |
| `-p <port>` | Port override for network targets |
| `-i <key>` | Path to private key file (for SSH) |
| `-X <method>` | HTTP method (GET, POST, PUT, DELETE) |
| `-H <header>` | Custom HTTP header (can be repeated) |

---

## AI Integration (`--ai`)

`why` is **100% functional and deterministic without AI**. When you want extended natural-language reasoning or tailored fix playbooks, enable `--ai`:

```bash
why ssh deploy@prod.internal --ai
```

`why` automatically detects your preferred backend:

1. **Local & Offline (Ollama)**: Zero API keys needed.
   ```bash
   ollama run llama3.2
   ```
2. **Google Gemini**:
   ```bash
   export GEMINI_API_KEY="your-gemini-key"
   ```
3. **OpenAI / vLLM / LocalAI**:
   ```bash
   export OPENAI_API_KEY="your-openai-key"
   # Optional custom endpoint:
   export OPENAI_BASE_URL="http://localhost:8000/v1"
   ```
4. **Anthropic Claude**:
   ```bash
   export ANTHROPIC_API_KEY="your-anthropic-key"
   ```

---

## Machine-Readable Failure Graph (`--json`)

Every diagnostic check produces a strongly typed JSON schema designed for CI pipelines, scripts, and monitoring:

```bash
why curl https://api.example.com/admin --json | jq .
```

```json
{
  "target": "https://api.example.com/admin",
  "protocol": "http",
  "timestamp": "2026-09-19T14:59:30Z",
  "status": "failed",
  "failed_at": "http_response",
  "total_elapsed": "142ms",
  "checks": [
    {
      "name": "DNS Resolution",
      "stage": "dns",
      "status": "passed",
      "summary": "Resolved api.example.com -> 104.21.5.12"
    },
    {
      "name": "TCP Connect :443",
      "stage": "tcp",
      "status": "passed",
      "summary": "Connected in 32ms"
    },
    {
      "name": "TLS Handshake",
      "stage": "tls",
      "status": "passed",
      "summary": "TLS 1.3 negotiated"
    },
    {
      "name": "HTTP GET /admin",
      "stage": "http",
      "status": "failed",
      "error": "HTTP Error 403: 403 Forbidden",
      "evidence": {
        "status_code": 403,
        "content_type": "text/html"
      }
    }
  ],
  "causes": [
    {
      "explanation": "The server understood the request but refuses to authorize it (Forbidden).",
      "confidence": "high",
      "likely": true,
      "remediation": [
        "Your IP address may be blocked by a Web Application Firewall (Cloudflare, AWS WAF, or iptables)",
        "Your user/role lacks permission or scope to access this specific resource path"
      ]
    }
  ]
}
```

---

## Architecture & Design Principles

See [docs/architecture.md](docs/architecture.md) for full architectural specifications and sequence diagrams.

1. **Don't Print in Plugins**: Adapters collect structured facts. They never print formatted strings.
2. **Deterministic First**: Diagnostics must be testable, fast, and reproducible without network LLM latency.
3. **Extensible Adapters**: Adding new protocol support (Docker, Kubernetes, Git, Database) is as simple as implementing the `Adapter` interface. See [docs/plugins.md](docs/plugins.md).

---

## Roadmap

Check out our [GitHub Issues](https://github.com/kavix/why/issues) for the active roadmap milestones:

- [x] **v0.1**: Core Diagnostic Engine with SSH, HTTP/curl, DNS, TLS, and TCP adapters
- [x] **v0.1**: Deterministic Causal Reasoning Engine (`--explain`)
- [x] **v0.1**: Machine-readable Failure Graph (`--json`)
- [x] **v0.1**: AI Causal Troubleshooting (`--ai` with Ollama, Gemini, OpenAI, Claude)
- [ ] **v0.2**: Git Adapter (`why git push`, `why git fetch` - auth, upstream tracking, SSH keys, hooks)
- [ ] **v0.2**: Docker Adapter (`why docker compose up`, daemon sockets, port collisions, OOM kills)
- [ ] **v0.3**: Kubernetes Adapter (`why k8s pod/foo`, CrashLoopBackOff, ImagePullBackOff, OOMKilled)
- [ ] **v0.3**: Systemd Adapter (`why systemd nginx`, unit failures, exit codes, dependency deadlocks)

See [ROADMAP.md](ROADMAP.md) for the complete phase-by-phase release milestones and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for technical specifications.

---

## Documentation Index

| Guide | Description |
|---|---|
| **[Architecture & Philosophy](docs/architecture.md)** | Deep dive on the failure graph model, sequence diagrams, and causal inference layer |
| **[Custom Adapters Tutorial](docs/plugins.md)** | How to implement a new diagnostic adapter in under 50 lines of Go |
| **[Roadmap](ROADMAP.md)** | Detailed phase-by-phase deliverables from Alpha (v0.1.0) to General Availability (v1.0.0) |
| **[Implementation Plan](IMPLEMENTATION_PLAN.md)** | Engineering specs, protocol contracts, privacy standards, and test matrices |
| **[Contributing Guide](CONTRIBUTING.md)** | Dev environment setup, conventional commits format, and pull request checklist |
| **[Security Policy](SECURITY.md)** | Vulnerability disclosure guidelines and SLA windows |
| **[Code of Conduct](CODE_OF_CONDUCT.md)** | Community pledge and standards (Contributor Covenant v2.1) |

---

## Community & Discussions

Have a question, an RFC proposal, or a wild failure story to share? Join our community!

- 💬 **[GitHub Discussions](https://github.com/kavix/why/discussions)**:
  - 📢 [Announcements](https://github.com/kavix/why/discussions/categories/announcements): Latest updates and release notes
  - 💡 [RFC & Ideas](https://github.com/kavix/why/discussions/categories/ideas): Propose new adapters and protocol ideas
  - 💬 [Q&A](https://github.com/kavix/why/discussions/categories/q-a): Community support and configuration help
  - 🚀 [Show & Tell](https://github.com/kavix/why/discussions/categories/show-and-tell): Share real-world terminal failure traces
- 🌟 **[Good First Issues](https://github.com/kavix/why/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)**: Beginner-friendly tasks for new contributors.

---

## Contributing

Contributions are warmly welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md) to get started with development and submitting pull requests.

---

## License

`why` is open-source software licensed under the [MIT License](LICENSE).

