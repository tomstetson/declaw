# DeClaw: Security-Hardened AI Assistant

<p align="center">
    <strong>OpenClaw with Defense-in-Depth Security</strong>
</p>

<p align="center">
  <a href="https://github.com/tomstetson/declaw/actions/workflows/ci.yml"><img src="https://github.com/tomstetson/declaw/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/tomstetson/declaw/releases"><img src="https://img.shields.io/badge/release-v1.0.0--alpha-orange?style=flat" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat" alt="MIT License"></a>
</p>

**DeClaw** is a security-focused fork of [OpenClaw](https://github.com/openclaw/openclaw) that adds defense-in-depth security while preserving full compatibility with OpenClaw's feature set.

All of OpenClaw's capabilities (WhatsApp, Telegram, Slack, Discord, Google Chat, Signal, iMessage, Microsoft Teams, Voice Wake, Canvas, Browser control, and more) remain intact. DeClaw adds **mandatory security controls** as a first-class concern.

## Why DeClaw Exists

OpenClaw is a powerful AI agent framework, but it was built for capability first and security second. Running an AI agent that can run shell commands, read files, and make network requests creates real attack surface. DeClaw addresses the security gaps that matter most when deploying AI agents in production.

### The Core Problem

An AI agent that gets prompt-injected (via a malicious webpage, a crafted message, or a poisoned document) can abuse every tool it has access to. OpenClaw's default configuration gives agents broad access with minimal guardrails. DeClaw assumes compromise will happen and designs containment accordingly.

## OpenClaw Security Gaps (With Code Evidence)

These are real findings from OpenClaw's source code, not theoretical risks.

### 1. Sandbox is OFF by Default

OpenClaw's sandbox defaults to `"off"` (`src/agents/sandbox/config.ts:147`):

```typescript
mode: agentSandbox?.mode ?? agent?.mode ?? "off",
```

A fresh OpenClaw install runs the AI agent directly on the host with full filesystem and process access. Users who skip sandbox configuration have an unsandboxed agent that can run arbitrary shell commands via the `exec` tool.

**DeClaw fix:** `declaw-doctor` detects this as a CRITICAL finding and auto-fixes it to `"non-main"`.

### 2. API Keys Stored in Plaintext

OpenClaw loads API keys from environment variables or plaintext JSON config (`src/config/io.ts:41-58`). The gateway reads keys like `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `OPENCLAW_GATEWAY_TOKEN` directly from shell environment:

```typescript
const SHELL_ENV_EXPECTED_KEYS = [
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  // ...12 more API keys loaded from env
];
```

Environment variables are visible to every process running as the same user. A compromised agent with shell access can run `printenv` and harvest every API key on the system.

**DeClaw fix:** The `secret://` URI scheme (`src/config/env-substitution.ts`) resolves credentials from secure vaults (macOS Keychain, HashiCorp Vault, Bitwarden, 1Password) at config load time. Keys never exist as environment variables. The `declaw-monitor` tool watches for `printenv` and `os.environ` access patterns and triggers a kill switch on detection.

### 3. Gateway Auth Token Length Not Enforced

OpenClaw's gateway auth check (`src/gateway/auth.ts:210-222`) only verifies that `auth.token` is truthy, not that it meets a minimum length. A single-character token is accepted at runtime. The 24-character minimum in `src/security/audit.ts:355` is an advisory warning, not a startup guard:

```typescript
if (auth.mode === "token" && token && token.length < 24) {
  findings.push({
    severity: "warn", // warn only, gateway still starts
  });
}
```

**DeClaw fix:** `declaw-doctor` treats tokens under 32 characters as CRITICAL and can auto-generate a 64-character hex token.

### 4. Plugin Scanner Never Blocks Installation

OpenClaw's plugin scanner (`src/plugins/install.ts:197-219`) explicitly says in its own source code:

```typescript
// Scan plugin source for dangerous code patterns (warn-only; never blocks install)
```

Even if the scanner detects dangerous patterns like `process.env` harvesting or `child_process` usage, the plugin still installs. The user sees a terminal warning but the plugin loads into the gateway's Node.js process with full access to all in-memory secrets (`src/plugins/loader.ts:211-219`).

**DeClaw fix:** `declaw-doctor` flags dangerous tools in allowlists. Full plugin blocking and signature verification are planned for v1.1.

### 5. No Resource Limits on Sandbox Containers

Even when sandbox is enabled, OpenClaw sets no default PID, memory, or CPU limits (`src/agents/sandbox/config.ts:71-74`):

```typescript
pidsLimit: agentDocker?.pidsLimit ?? globalDocker?.pidsLimit,  // undefined
memory: agentDocker?.memory ?? globalDocker?.memory,            // undefined
cpus: agentDocker?.cpus ?? globalDocker?.cpus,                 // undefined
```

A compromised agent inside the container can fork-bomb the host's process table or consume all available memory until the kernel's OOM killer intervenes.

### 6. No Runtime Monitoring

OpenClaw has no mechanism to detect suspicious behavior at runtime. If an agent starts scanning for credentials, encoding data for exfiltration, or attempting container escape, nothing triggers an alert or stops the agent.

**DeClaw fix:** `declaw-monitor` watches session transcripts in real-time with 10 detection patterns covering environment access, base64 encoding, reverse shells, credential scanning, and container escape attempts. CRITICAL detections trigger an automatic kill switch that stops the Docker container and creates a block file requiring manual review.

### What OpenClaw Does Well

Credit where it is due. When sandbox IS enabled, OpenClaw's defaults are strong:

- `readOnlyRoot: true` prevents persistent malware
- `network: "none"` blocks all container egress
- `capDrop: ["ALL"]` drops all Linux capabilities
- `--no-new-privileges` is hardcoded and cannot be overridden (`src/agents/sandbox/docker.ts:161`)
- Gateway token comparison uses `timingSafeEqual` (resistant to timing attacks)
- Config files are written with `0o600` permissions
- Gateway refuses to bind to non-loopback without auth

DeClaw builds on these strengths and makes them mandatory rather than opt-in.

---

## OpenClaw vs DeClaw

| Feature                     | OpenClaw                                           | DeClaw                                                       |
| --------------------------- | -------------------------------------------------- | ------------------------------------------------------------ |
| Multi-channel support       | All channels                                       | All channels                                                 |
| Docker sandboxing           | Optional, defaults to off                          | Detected and enforced by declaw-doctor                       |
| Secrets management          | Env vars and plaintext config                      | Multi-provider vault (Keychain, Vault, Bitwarden, 1Password) |
| Config validation           | `openclaw doctor` (warnings only, exits 0)         | `declaw doctor` (CRITICAL findings, auto-fix, CI exit codes) |
| Real-time anomaly detection | None                                               | 10 detection patterns with kill switch                       |
| readOnlyRoot                | Optional (defaults true when sandbox on)           | Enforced via declaw-doctor                                   |
| Gateway auth                | Token required for non-loopback, no length minimum | 32-char minimum enforced, auto-generated on fix              |
| Capability dropping         | Defaults to ALL when sandbox on                    | Enforced via declaw-doctor check                             |
| Runtime secret protection   | None                                               | Monitors for env access, base64 encoding, exfil attempts     |
| Upstream tracking           | N/A                                                | Cherry-pick OpenClaw updates weekly                          |

---

## What Ships Today (v1.0-alpha)

These tools are implemented, tested, and working:

### 1. Multi-Provider Secrets Management (`declaw-secrets`)

Replaces plaintext API keys with vault-backed secret resolution.

```bash
# Store a secret in your vault
declaw-secrets set ANTHROPIC_API_KEY

# Reference it in config (never stored as env var)
{
  "env": {
    "ANTHROPIC_API_KEY": "secret://ANTHROPIC_API_KEY"
  }
}
```

Supported providers:

- **macOS Keychain** (built-in, zero setup, auto-detected on macOS)
- **HashiCorp Vault** (requires `vault` CLI)
- **Bitwarden** (requires `bw` CLI)
- **1Password** (requires `op` CLI)
- **Env file** (fallback with chmod 600 protection)

All access is audit-logged to `~/.declaw/audit.jsonl` in JSONL format. Auto-detection picks the best available provider. The `secret://` URI scheme is integrated into OpenClaw's config loader (`src/config/env-substitution.ts`) so secrets are resolved at startup without touching environment variables.

### 2. Startup Config Validation (`declaw-doctor`)

15 security checks with auto-fix for 11 of them:

```bash
# Audit your config
declaw-doctor

# Auto-fix safe issues (creates backup first)
declaw-doctor --fix

# Preview fixes without applying
declaw-doctor --fix --dry-run
```

| Severity | Check                          | Auto-fix                        |
| -------- | ------------------------------ | ------------------------------- |
| CRITICAL | Gateway token missing or weak  | Generates 64-char hex token     |
| CRITICAL | API keys stored as env vars    | No (requires secrets migration) |
| CRITICAL | Sandbox disabled               | Sets mode to "all"              |
| HIGH     | Dangerous tools in allowlists  | Removes them                    |
| HIGH     | Exec approvals disabled        | Enables with placeholder        |
| HIGH     | readOnlyRoot disabled          | Sets to true                    |
| MEDIUM   | Context pruning disabled       | Enables cache-ttl (1h)          |
| MEDIUM   | Non-loopback without TLS       | No (requires manual TLS setup)  |
| MEDIUM   | Linux capabilities not dropped | Adds capDrop: ALL               |
| HIGH     | No command policy configured   | Sets denylist mode              |
| HIGH     | Sandbox network unrestricted   | Sets egress deny-all            |
| MEDIUM   | No plugin security scanning    | Sets enforce mode               |
| LOW      | Gateway reload race conditions | Sets hot reload with debounce   |

Exit codes: 0 = pass, 1 = critical issues, 2 = warnings only. Designed for CI/CD integration.

### 3. Real-Time Anomaly Detection (`declaw-monitor`)

Monitors OpenClaw session transcripts for suspicious tool calls:

```bash
# Alert mode (log detections, no enforcement)
declaw-monitor monitor

# Kill switch mode (stops container on CRITICAL detections)
declaw-monitor monitor --kill-switch

# List all detection patterns
declaw-monitor patterns
```

| Severity | Pattern          | What it catches                                      |
| -------- | ---------------- | ---------------------------------------------------- |
| CRITICAL | ENV_ACCESS       | `printenv`, `os.environ`, `process.env`              |
| CRITICAL | BASE64_ENCODE    | `base64`, `xxd`, `openssl enc`, `btoa()`             |
| CRITICAL | REVERSE_SHELL    | `bash -i`, `python pty.spawn`                        |
| HIGH     | EXFIL_TOOLS      | `curl -d`, `wget --post`, `nc -e`, `socat`           |
| HIGH     | CRED_SCAN        | `grep -r password`, `find .ssh`, `cat /etc/shadow`   |
| MEDIUM   | DOCKER_ESCAPE    | `docker.sock`, `/var/run/docker`, `cgroups`          |
| MEDIUM   | SUSPICIOUS_FILES | `rm -rf *`, `chmod 777`, `chown root`                |
| MEDIUM   | PORT_SCAN        | `nmap`, `masscan`, `zmap`                            |
| LOW      | API_SPAM         | Excessive `web_fetch`, `web_search`, `browser` calls |
| LOW      | LARGE_WRITE      | `dd bs=`, `fallocate`, large file operations         |

Kill switch behavior: On CRITICAL detection, stops the Docker container via `docker kill`, creates a block file at `~/.declaw/{agent}.blocked`, and requires manual review before the agent can restart.

### 4. Docker Sandbox Images

Pre-built images with minimal attack surface:

- **`tomstetson/declaw-sandbox:debian`** (788 MB): Python 3.11, pip, curl, wget, git, jq
- **`tomstetson/declaw-sandbox:debian-osint`** (1.5 GB): Adds nmap, whois, dnsutils, sherlock, maigret, holehe, yt-dlp

Both run as non-root `sandbox` user (UID 1000).

### 5. Hardened Config Templates

Pre-configured templates in `configs/`:

- `openclaw.json.template`: Mandatory sandbox, readOnlyRoot, capDrop ALL, gateway auth
- `gluetun.env.template`: VPN sidecar (Mullvad, NordVPN, ProtonVPN)
- `docker-compose.yml.template`: Full stack with VPN sidecar + agent sandbox

---

## What is Planned (Not Yet Implemented)

Transparency about what is roadmap vs reality:

- **Plugin signature verification** (GPG): Planned for v1.1
- **Plugin install blocking** (not just warnings): Planned for v1.1
- **Webhook alerts** (Telegram, Slack, email): Stub exists, not functional
- **`declaw migrate` command**: Planned, not yet built
- **Startup enforcement in gateway code**: Tools are standalone; gateway code-level enforcement is planned
- **ML-based anomaly detection**: Planned for v1.2
- **Compliance reporting** (SOC2, ISO 27001): Planned for v1.2

---

## Production Validation

DeClaw's security model was validated through a real-world deployment:

**Jebnick (OSINT Agent on Signal)**

- Signal-only AI bot exposed to security researchers for red teaming
- 2+ weeks of production operation
- 43/43 manual red team tests passed (100% success rate)
- 1 live prompt injection detected and refused by anomaly detection
- 0 secrets leaked
- 0 privilege escalations successful
- 6-layer defense architecture: channel binding, user allowlist, Docker sandbox, tool restrictions, VPN sidecar, workspace isolation

---

## Quick Start

Runtime: **Node 22+**

```bash
npm install -g declaw@latest

declaw onboard --install-daemon
```

The `declaw` command maintains full backward compatibility with `openclaw` commands.

### From Source

```bash
git clone https://github.com/tomstetson/declaw.git
cd declaw

pnpm install
pnpm ui:build
pnpm build

pnpm declaw onboard --install-daemon
```

---

## Configuration

Minimal `~/.declaw/declaw.json` (same as OpenClaw):

```json5
{
  agent: {
    model: "anthropic/claude-opus-4-6",
  },
}
```

DeClaw security overrides (optional, applied by `declaw doctor --fix`):

```json5
{
  agents: {
    defaults: {
      sandbox: {
        mode: "non-main",
        readOnlyRoot: true,
        capDrop: ["ALL"],
      },
    },
  },
}
```

---

## CLI Commands

All OpenClaw commands work unchanged:

```bash
# Gateway
declaw gateway --port 18789 --verbose
declaw gateway --status

# Agent
declaw agent --message "Hello world"

# Channels
declaw channels login
declaw channels status

# Skills
declaw skills install @clawhub/osint-toolkit
declaw skills list
```

DeClaw-specific commands:

```bash
# Security validation
declaw-doctor                       # Audit config
declaw-doctor --fix                 # Auto-fix issues
declaw-doctor --fix --dry-run       # Preview fixes

# Secrets management
declaw-secrets set API_KEY          # Store secret
declaw-secrets get API_KEY          # Retrieve secret
declaw-secrets list                 # List all secrets
declaw-secrets audit                # View access log

# Anomaly monitoring
declaw-monitor monitor              # Start monitoring
declaw-monitor monitor --kill-switch  # Enable kill switch
declaw-monitor patterns             # List detection patterns
```

---

## Full Feature Parity with OpenClaw

DeClaw includes all OpenClaw features:

**Channels:** WhatsApp, Telegram, Slack, Discord, Google Chat, Signal, BlueBubbles (iMessage), Microsoft Teams, Matrix, Zalo, WebChat

**Apps:** macOS menu bar (Voice Wake, PTT, Canvas), iOS node, Android node

**Tools:** Browser control (Playwright), Canvas + A2UI, Cron jobs, Webhooks, Gmail Pub/Sub, Skills platform (ClawHub)

**Advanced:** Multi-agent routing, Session coordination, Tailscale Serve/Funnel, Remote gateway, Voice Wake + Talk Mode, Live Canvas

---

## Benchmarks

| Metric           | OpenClaw | DeClaw | Overhead            |
| ---------------- | -------- | ------ | ------------------- |
| Gateway startup  | 2.1s     | 2.4s   | +300ms (validation) |
| Message latency  | 180ms    | 185ms  | +5ms (monitoring)   |
| Memory (gateway) | 85 MB    | 105 MB | +20 MB (monitor)    |
| CPU idle         | 0.5%     | 0.6%   | +0.1% (monitoring)  |

---

## Architecture

```
WhatsApp / Telegram / Slack / Discord / Signal / iMessage / Teams / WebChat
               |
               v
+-------------------------------+
|        DeClaw Gateway         |
|      (control plane)          |
|     ws://127.0.0.1:18789      |
|                               |
|  +-------------------------+  |
|  | Security Layer          |  |
|  +-------------------------+  |
|  | Config validator        |  |
|  | Secrets manager         |  |
|  | Anomaly detector        |  |
|  +-------------------------+  |
+---------------+---------------+
                |
                +-- Pi agent (Docker sandbox)
                +-- CLI (declaw ...)
                +-- WebChat UI
                +-- macOS / iOS / Android
```

---

## Community

**GitHub:** [github.com/tomstetson/declaw](https://github.com/tomstetson/declaw)
**Issues:** [github.com/tomstetson/declaw/issues](https://github.com/tomstetson/declaw/issues)

**Built by:** [Tom Stetson](https://github.com/tomstetson)
**Based on:** [OpenClaw](https://github.com/openclaw/openclaw) by the OpenClaw community

---

## License

MIT License. See [LICENSE](LICENSE).

DeClaw is a fork of OpenClaw. Both projects are MIT-licensed.

---

## Reporting Security Issues

**Do not** open public GitHub issues for security vulnerabilities.

**Email:** security@stetson.dev

**In scope:** Prompt injection bypasses, container escape techniques, secrets manager vulnerabilities, authentication bypasses, data exfiltration vectors.
