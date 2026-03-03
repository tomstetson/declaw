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
- [x] End-to-end integration test (config load with real secret:// resolution)
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

## Phase 3: Observability (Complete)

- [x] **Unified event schema** — `DeclawSecurityEvent` type with 14 categories,
      typed severities and outcomes. Canonical schema shared between TypeScript
      and Python. (src/lib/declaw-events.ts, scripts/declaw-common/event_schema.py,
      18 tests)
- [x] **Structured audit logger** — JSONL audit trail at `~/.declaw/audit.jsonl`.
      `emitDeclawEvent()` writes events, increments metrics, and forwards to SIEM.
      All TypeScript hooks (exec, egress, secrets, config) instrumented.
      (src/lib/declaw-audit.ts, 19 vitest tests)
- [x] **In-memory metrics** — per-category event counters, total/error counts,
      auto-incremented from emitDeclawEvent(). (src/lib/declaw-metrics.ts, 9 tests)
- [x] **Python tool migration** — declaw-secrets, declaw-doctor, declaw-monitor
      all emit unified events via shared event_schema.py. (38 new pytest tests)
- [x] **SIEM transport** — fire-and-forget HTTP POST to configurable endpoint,
      best-effort delivery. Config: `declaw.siem`. (5 vitest tests)
- [x] **Observability config types** — `DeclawObservabilityConfig` (audit, siem,
      metrics) integrated into `OpenClawConfig.declaw`. (src/config/types.declaw.ts)
- [x] **Audit CLI** — `declaw-audit` tool for query, export (JSON/CSV), and stats
      with time-range filters, category/severity/source filtering. (23 pytest tests)
- [x] **Doctor O1/O2 checks** — O1: audit trail writable, O2: SIEM endpoint
      validation. Total doctor checks: 15. (15 new pytest tests)
- [ ] Prometheus metrics exporter (expose counters via HTTP endpoint)
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

Phases 0-3 are complete. DeClaw now covers secrets management, config validation,
runtime monitoring, sandbox enforcement, command/egress policy, plugin security,
and unified observability (audit trail, metrics, SIEM transport, audit CLI).
Phase 4 focuses on advanced isolation (gVisor, mTLS, secret rotation).

Remaining low-priority items:

- Remove declaw-secrets-v1 from bin exports (Phase 1 cleanup)
- Prometheus metrics HTTP endpoint (Phase 3 stretch)
- Dashboard UI (Phase 3 stretch)
