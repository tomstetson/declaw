# DeClaw Roadmap

## Phase 0: Foundation (Complete)

- [x] Fork OpenClaw, establish repo structure
- [x] Implement declaw-secrets (5 providers, auto-detection, audit logging)
- [x] Implement declaw-doctor (10 security checks, 8 auto-fixes)
- [x] Implement declaw-monitor (10 detection patterns, kill switch)
- [x] Integrate secret:// URI into env-substitution.ts
- [x] Create secrets.ts TypeScript bridge
- [x] DeClaw branding (package.json, README, CHANGELOG-DECLAW)

## Phase 1: Hardening (In Progress)

- [x] Rebuild on latest upstream (v2026.2.24)
- [x] Fix CI for private fork (runners, workflows, release-check)
- [x] Fix Python tool bugs (keychain parsing, monitor regex, doctor placeholder)
- [x] Add vitest tests for secrets.ts and secret:// integration (41 tests)
- [x] Replace upstream CLAUDE.md/AGENTS.md with DeClaw-specific docs
- [x] Create ADRs for key architectural decisions
- [ ] Add pytest infrastructure for Python tools
- [ ] Update SECURITY.md for DeClaw
- [ ] Create ARCHITECTURE.md with Mermaid diagrams
- [ ] End-to-end integration test (config load with real secret:// resolution)
- [ ] Remove declaw-secrets-v1 from bin exports (legacy, replaced by v2)

## Phase 2: Security Enforcement (Not Started)

Command allowlist and egress filtering are the two biggest security gaps
remaining. Without these, a compromised agent can run arbitrary commands and
exfiltrate data to any endpoint.

- [ ] **Command allowlist enforcement** -- restrict which shell commands agents
      can execute. Allowlist in config, deny by default, audit all denials.
- [ ] **Egress filtering** -- restrict outbound network from sandboxed containers.
      DNS allowlist, block non-allowlisted IPs, log violations.
- [ ] **Webhook alerts** -- implement `_send_alert()` stub in declaw-monitor.
      Support Telegram, Slack, email (SMTP), custom webhook.
- [ ] **Plugin security scanning** -- pre-install GPG signature verification,
      AST-based dangerous pattern detection, sandbox compatibility checks.

## Phase 3: Observability (Not Started)

- [ ] Structured logging (JSON format for all DeClaw components)
- [ ] Prometheus metrics exporter (secret resolution latency, detection counts)
- [ ] Compliance audit trail export (SOC2-compatible format)
- [ ] Dashboard for detection events and secret access patterns

## Phase 4: Advanced Isolation (Not Started)

- [ ] gVisor or Firecracker microVM support as sandbox alternative
- [ ] mTLS between gateway and agents
- [ ] Secret rotation detection and auto-reload
- [ ] Per-agent resource limits (CPU, memory, network bandwidth)

## Upstream Sync Schedule

- **Frequency**: Rebuild on each upstream minor release (roughly biweekly)
- **Process**: See ADR-003 (docs/adr/003-fork-strategy.md)
- **Current base**: OpenClaw v2026.2.24
- **Integration points to watch**: `src/config/env-substitution.ts` (primary),
  `src/agents/sandbox/config.ts` (sandbox defaults)

## Priorities

Phase 2 items (command allowlist, egress filtering) are the highest-impact
remaining work. They close the two largest attack vectors: arbitrary command
execution and unrestricted network access. Everything else is defense-in-depth
layering on top of these controls.
