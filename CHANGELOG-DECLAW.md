# DeClaw Changelog

All notable changes to DeClaw (security-hardened OpenClaw fork) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-02-10

### Added - Security Features

**Multi-Provider Secrets Management**

- Added `declaw-secrets` CLI tool for secure secrets storage
- Support for 5 providers: macOS Keychain, HashiCorp Vault, Bitwarden, 1Password, env file
- Auto-detection of best available provider
- `secret://` URI scheme for config references
- Audit logging for all secret access (`~/.declaw/audit.log`)

**Startup Config Validation**

- Added `declaw doctor` security auditor
- 13 security checks (3 CRITICAL, 5 HIGH, 4 MEDIUM, 1 LOW)
- Auto-fix for 8/10 checks via `--fix` flag
- Fail-fast validation at gateway startup (refuses to start if critical issues found)
- Backup creation before auto-fixes

**Real-Time Anomaly Detection**

- Added `declaw-monitor` daemon for session transcript monitoring
- 10 detection patterns with regex matching
- Kill switch for CRITICAL detections (stops container, blocks restart)
- Audit trail in `~/.declaw/monitor-audit.log` (JSONL format)
- < 100ms detection latency

**Mandatory Docker Sandboxing**

- Enforced `sandbox.mode: "non-main"` by default
- Enforced `readOnlyRoot: true` (prevents persistent malware)
- Enforced `capDrop: ["ALL"]` (minimal Linux capabilities)
- VPN sidecar integration (Gluetun/Mullvad support)
- Explicit `_dangerouslyDisableSandbox` escape hatch

**Plugin Security Scanning (Complete)**

- [x] Policy evaluation engine (enforce/warn/off modes)
- [x] Capability restriction mapping (exec, network, env, eval, crypto-mining)
- [x] SHA256 integrity verification (`sha256sum`-compatible checksum files)
- [x] Sandbox compatibility checking (network vs none, exec vs capDrop)
- [x] Trusted origin support (bundled plugins skip scanning)
- [x] Doctor check M4 with auto-fix (sets enforce mode + default capabilities)
- [x] Config: `plugins.pluginSecurity` in openclaw.json

### Changed - Breaking Changes

**Gateway Authentication**

- Gateway auth token now **mandatory** (64-char minimum)
- `gateway.auth.mode: "token"` enforced by default
- `declaw doctor --fix` auto-generates strong token

**Secrets Management**

- API keys in environment variables **blocked** by default
- Config must use `secret://KEY_NAME` references
- Migration wizard planned: `declaw migrate` (not yet built)

**Sandbox Mode**

- Non-main sessions **must** use Docker sandbox
- `sandbox.mode: "off"` rejected at startup
- Use `_dangerouslyDisableSandbox: true` to override (with warning)

**Context Pruning**

- `contextPruning.mode: "cache-ttl"` enabled by default
- `contextPruning.ttl: "1h"` default
- Prevents 200K token overflow (avoids manual session cleanup)

### Changed - Non-Breaking

**CLI Backward Compatibility**

- `openclaw` command aliased to `declaw` (full compatibility)
- All existing OpenClaw scripts work unchanged
- `~/.openclaw` config directory supported (fallback to `~/.declaw`)

**Config Format**

- 99% compatible with OpenClaw configs
- New `security` section for DeClaw-specific settings (optional)
- Existing OpenClaw configs work with minimal changes

**Documentation**

- New README emphasizing security features
- Comparison table (OpenClaw vs DeClaw)
- Migration guide for OpenClaw users
- Upstream sync strategy documentation

### Fixed

**Security Issues Resolved**

- Gateway auth token weakness (C1)
- API keys in environment variables (C2)
- Sandbox disabled by default (C3)
- Dangerous tools allowed (H1)
- Exec approvals disabled (H2)
- readOnlyRoot disabled (H3)
- Context pruning disabled (M1)
- Gateway non-loopback without TLS (M2)
- No capability drop (M3)
- Reload race conditions (L1)

### Technical Details

**Fork Information**

- Based on OpenClaw v2026.2.24
- Upstream remote: `git@github.com:openclaw/openclaw.git`
- Sync strategy: Clean rebuild per tagged release (see docs/adr/003-fork-strategy.md)
- Maintained by: Tom Stetson (@tomstetson)

**Performance Impact**

- Gateway startup: +300ms (config validation)
- Message latency: +5ms (anomaly monitoring)
- Memory overhead: +20 MB (monitor daemon)
- CPU idle: +0.1% (monitoring)
- Container image: +100 MB (security tools)

**Dependencies Added**

- None (Python 3.8+ for standalone tools)
- Security tools bundled as scripts (`scripts/declaw-*`)

**Testing**

- All OpenClaw tests pass unchanged
- Additional security tests added:
  - Config validation tests (13 checks)
  - Secrets manager tests (5 providers)
  - Anomaly detection tests (10 patterns)
  - Sandbox enforcement tests

---

## [Unreleased] - v1.1.0 (In Progress)

### Planned - v1.1 Features

**Plugin Security (Q2 2026)**

- [ ] GPG signature verification for ClawHub plugins
- [ ] AST-based dangerous pattern scanning
- [ ] Sandbox compatibility pre-flight checks
- [ ] Plugin permission manifest

**Webhook Alerts (Complete)**

- [x] Telegram bot notifications (telegram://BOT_TOKEN@CHAT_ID)
- [x] Slack webhook integration (slack:// or hooks.slack.com URLs)
- [x] Email alerts (smtp://user:pass@host:port?to=addr)
- [x] Custom webhook support (any HTTPS URL, JSON POST)
- [x] Multi-destination support (comma-separated URLs)
- [x] `test-alert` CLI subcommand for verifying webhook config

**ML-Based Anomaly Detection (Q3 2026)**

- [ ] Behavioral baselining (learn normal patterns)
- [ ] Anomaly scoring (replace regex patterns)
- [ ] Auto-tuning detection thresholds
- [ ] Multi-agent correlation

**Compliance Reporting (Q3 2026)**

- [ ] SOC2 audit trail export
- [ ] ISO 27001 compliance checks
- [ ] CIS benchmark validation
- [ ] PDF report generation

### Planned - v1.2 Features (Q4 2026)

**Zero-Trust Networking**

- [ ] mTLS between gateway and agents
- [ ] WireGuard mesh for multi-host deployments
- [ ] Certificate rotation automation

**Hardware Security Module (HSM)**

- [ ] YubiKey integration for secrets
- [ ] TPM 2.0 support for Linux hosts
- [ ] macOS Secure Enclave integration

**SIEM Integration**

- [ ] Splunk forwarder
- [ ] Elastic (ELK) integration
- [ ] DataDog APM
- [ ] Prometheus metrics exporter

**Advanced Sandboxing**

- [ ] gVisor runtime support
- [ ] Firecracker microVM integration
- [ ] Kata Containers support

---

## Upstream Sync Log

Track OpenClaw upstream merges here.

### 2026-02-25 - Rebuild on v2026.2.24

- Rebuilt from: `openclaw/openclaw@v2026.2.24`
- Strategy: Clean rebuild (see docs/adr/003-fork-strategy.md)
- Adapted `env-substitution.ts` to upstream's new `parseEnvTokenAt` refactor
- Updated CI workflows (Blacksmith runners removed, release-check disabled)
- Status: Clean rebuild, types/lint/tests pass

### 2026-02-10 - Initial Fork

- Forked from: `openclaw/openclaw@v2026.2.9`
- Status: Clean fork, no conflicts

---

## Migration Notes

### From OpenClaw v2026.2.9

**Auto-Fixable Issues:**

1. Run `declaw-doctor --fix` to auto-fix config
2. Gateway token generated automatically
3. Sandbox mode enabled for non-main sessions
4. Context pruning configured

**Manual Steps Required:**

1. Migrate API keys to secrets manager:
   ```bash
   declaw-secrets set ANTHROPIC_API_KEY
   declaw-secrets set OPENAI_API_KEY
   ```
2. Update config to use `secret://` references
3. Review and approve auto-fixes
4. Test in dev environment before production

**Rollback Plan:**

1. Reinstall OpenClaw: `npm install -g openclaw@2026.2.9`
2. Restore config backup: `cp ~/.openclaw/openclaw.json.bak ~/.openclaw/openclaw.json`
3. Restart gateway: `openclaw gateway restart`

---

## Security Advisories

### SA-2026-001 - API Keys in Environment Variables (CRITICAL)

**Severity:** CRITICAL
**Affected:** OpenClaw < 2026.2.9, DeClaw < 1.0.0
**Fixed in:** DeClaw 1.0.0
**Description:** API keys stored in environment variables are visible to all processes and logged in plaintext.
**Mitigation:** Use `declaw-secrets` to store keys in secure vaults (Keychain, Vault, etc.)

### SA-2026-002 - Sandbox Disabled by Default (CRITICAL)

**Severity:** CRITICAL
**Affected:** OpenClaw < 2026.2.9 (when not manually configured)
**Fixed in:** DeClaw 1.0.0 (enforced)
**Description:** Non-main sessions can execute arbitrary code on host without isolation.
**Mitigation:** Set `sandbox.mode: "non-main"` and `readOnlyRoot: true` in config.

### SA-2026-003 - readOnlyRoot Disabled (HIGH)

**Severity:** HIGH
**Affected:** OpenClaw < 2026.2.9 (when not manually configured)
**Fixed in:** DeClaw 1.0.0 (enforced)
**Description:** Agents can persist malware in container filesystem across sessions.
**Mitigation:** Set `readOnlyRoot: true` in sandbox config.

### SA-2026-004 - Gateway Auth Token Weak/Missing (HIGH)

**Severity:** HIGH
**Affected:** OpenClaw < 2026.2.9 (when auth disabled)
**Fixed in:** DeClaw 1.0.0 (enforced)
**Description:** Unauthenticated access to Gateway WebSocket allows full control.
**Mitigation:** Set `gateway.auth.token` to 64-char random hex string.

---

## Credits

**DeClaw Project**

- Author: Tom Stetson (@tomstetson)
- Contributors: See [CONTRIBUTORS.md](CONTRIBUTORS.md)

**Based on OpenClaw**

- Original author: Peter Steinberger (@steipete)
- Contributors: See [OpenClaw CONTRIBUTORS](https://github.com/openclaw/openclaw/graphs/contributors)
- Project: https://github.com/openclaw/openclaw

**Special Thanks**

- Mario Zechner for [pi-mono](https://github.com/badlogic/pi-mono)
- Security researchers who reported vulnerabilities responsibly
- OpenClaw community for building the foundation

---

**License:** MIT (same as OpenClaw)
**Upstream:** https://github.com/openclaw/openclaw
**DeClaw:** https://github.com/tomstetson/declaw
