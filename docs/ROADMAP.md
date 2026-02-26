# DeClaw Roadmap

## Phase 0: Foundation (Complete)

- [x] Fork OpenClaw, establish repo structure
- [x] Implement declaw-secrets (5 providers, auto-detection, audit logging)
- [x] Implement declaw-doctor (10 security checks, 8 auto-fixes)
- [x] Implement declaw-monitor (10 detection patterns, kill switch)
- [x] Integrate secret:// URI into env-substitution.ts
- [x] Create secrets.ts TypeScript bridge
- [x] DeClaw branding (package.json, README, CHANGELOG-DECLAW)

## Phase 1: Hardening (Complete)

- [x] Rebuild on latest upstream (v2026.2.24)
- [x] Fix CI for private fork (runners, workflows, release-check)
- [x] Fix Python tool bugs (keychain parsing, monitor regex, doctor placeholder)
- [x] Add vitest tests for secrets.ts and secret:// integration (41 tests)
- [x] Replace upstream CLAUDE.md/AGENTS.md with DeClaw-specific docs
- [x] Create ADRs for key architectural decisions (3 ADRs)
- [x] Add pytest infrastructure for Python tools (143 tests)
- [x] Update SECURITY.md for DeClaw
- [x] Create ARCHITECTURE.md with Mermaid diagrams
- [ ] End-to-end integration test (config load with real secret:// resolution)
- [ ] Remove declaw-secrets-v1 from bin exports (legacy, replaced by v2)

## Phase 2: Security Enforcement (Complete)

- [x] **Command allowlist enforcement** — admin-enforced command policy that
      runs before OpenClaw's user-managed exec-approvals. Supports allowlist
      and denylist modes with wildcard patterns. Config: `tools.exec.commandPolicy`.
      (src/lib/declaw-command-policy.ts, 41 vitest tests)
- [x] **Egress filtering** — egress policy enforcement for sandbox containers.
      Modes: deny-all (force network=none), restricted (DNS filtering),
      unrestricted (warn). Config: `sandbox.docker.egressPolicy`.
      (src/lib/declaw-egress-policy.ts, 20 vitest tests)
- [x] **Doctor checks for Phase 2** — H4 (command policy) and H5 (egress policy)
      added to declaw-doctor with auto-fix support. (18 new pytest tests)
- [x] **Webhook alerts** — AlertDispatcher with 4 providers: Telegram Bot API,
      Slack incoming webhook, SMTP email, generic HTTPS webhook. Comma-separated
      multi-destination support, retry logic, `test-alert` CLI subcommand.
      (37 new pytest tests)
- [x] **Plugin security scanning** — policy evaluation engine with enforce/warn/off
      modes, capability restriction (exec/network/env/crypto-mining), SHA256
      integrity verification, sandbox compatibility checking. Config:
      `plugins.pluginSecurity`. Doctor check M4 with auto-fix.
      (src/lib/declaw-plugin-security.ts, 42 vitest + 10 pytest tests)

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
  `src/agents/sandbox/config.ts` (sandbox defaults), `src/agents/bash-tools.exec.ts`
  (command policy hook), `src/config/types.tools.ts` (commandPolicy config),
  `src/config/types.sandbox.ts` (egressPolicy config)

## Priorities

Phase 2 is complete. All four security enforcement features are implemented:
command allowlist (arbitrary exec), egress filtering (network exfiltration),
webhook alerts (real-time notifications), and plugin security scanning
(supply-chain). Phase 3 focuses on observability.
