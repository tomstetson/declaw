# DeClaw - Security-Hardened OpenClaw Fork

Private repo: https://github.com/tomstetson/declaw
Upstream: https://github.com/openclaw/openclaw (v2026.2.24 base)

## What DeClaw Is

A security-hardened fork of OpenClaw that adds defense-in-depth: secrets management,
config validation, runtime monitoring, and sandbox enforcement. Retains full OpenClaw
feature set (multi-channel AI gateway for WhatsApp, Telegram, Slack, Discord, Signal, etc.)
while closing security gaps in the default configuration.

## DeClaw-Specific Code

All DeClaw additions live in these locations:

- `src/lib/secrets.ts` - TypeScript bridge to declaw-secrets (execFileSync to Python)
- `src/lib/declaw-command-policy.ts` - Command allowlist/denylist enforcement (Phase 2)
- `src/lib/declaw-egress-policy.ts` - Egress filtering for sandbox containers (Phase 2)
- `src/lib/declaw-plugin-security.ts` - Plugin security scanning policy (Phase 2)
- `src/lib/declaw-events.ts` - Canonical security event schema (Phase 3)
- `src/lib/declaw-audit.ts` - Structured audit logger → ~/.declaw/audit.jsonl (Phase 3)
- `src/lib/declaw-metrics.ts` - In-memory metrics counters, auto-incremented (Phase 3)
- `src/config/env-substitution.ts` - `secret://` URI integration (lines 92-124)
- `scripts/declaw-secrets/` - Multi-provider secrets manager (Python 3.8+)
- `src/config/types.declaw.ts` - Observability config types (Phase 3)
- `scripts/declaw-doctor/` - Config security validator (Python 3.8+, 15 checks)
- `scripts/declaw-audit/` - Compliance query/export CLI (Python 3.8+)
- `scripts/declaw-monitor/` - Runtime anomaly detector (Python 3.8+)
- `scripts/declaw-common/` - Shared Python modules (event_schema.py)
- `docs/adr/004-unified-observability.md` - ADR for Phase 3 architecture
- `README.md` - DeClaw-specific README
- `CHANGELOG-DECLAW.md` - DeClaw changelog
- `SECURITY.md` - Security policy

Upstream files modified for DeClaw integration (keep minimal):

- `src/agents/bash-tools.exec.ts` - Command policy hook + audit event (import + 15 lines)
- `src/agents/bash-tools.exec-types.ts` - `commandPolicy` in ExecToolDefaults
- `src/agents/sandbox/config.ts` - Egress policy enforcement + audit events (import + 30 lines)
- `src/config/env-substitution.ts` - secret:// audit events on resolve success/failure
- `src/config/types.tools.ts` - `commandPolicy` in ExecToolConfig
- `src/config/types.sandbox.ts` - `egressPolicy` in SandboxDockerSettings
- `src/config/types.plugins.ts` - `pluginSecurity` in PluginsConfig
- `src/config/types.openclaw.ts` - `declaw?` observability config field
- `src/config/types.ts` - barrel export for types.declaw.ts

## Commands

- Install deps: `pnpm install`
- Type check: `pnpm tsgo`
- Lint + format: `pnpm check`
- Format fix: `pnpm format:fix`
- Tests: `pnpm test` (vitest, all OpenClaw + DeClaw tests)
- Single test: `pnpm test src/lib/secrets.test.ts`
- Build: `pnpm build`
- Python tools (standalone): `python3 scripts/declaw-secrets/declaw-secrets --help`

## Architecture

```
User Config (openclaw.json)
    |
    v
env-substitution.ts --- secret:// URIs ---> secrets.ts ---> declaw-secrets (Python)
    |                                                            |
    v                                                            v
OpenClaw gateway startup                              Keychain / Vault / 1Password / Bitwarden / .env
    |
    v
declaw-doctor validates config at startup (Python subprocess)
declaw-monitor watches session transcripts (Python daemon)
```

The `secret://` URI scheme hooks into OpenClaw's config loading pipeline. In
`substituteString()`, we check for `secret://` before the `${}` env var parsing.
This means `secret://ANTHROPIC_API_KEY` resolves from the vault, while
`${ANTHROPIC_API_KEY}` still resolves from environment variables.

## Gotchas

- `secrets.ts` resolves the owning DeClaw/OpenClaw package from its module URL,
  then launches bundled Python with shell-free arguments. Python 3 must be on PATH.
- Python tools are standalone scripts (shebang `#!/usr/bin/env python3`), not
  importable modules. They communicate via stdout/stderr/exit codes.
- `declaw-monitor` webhook alerts use stdlib only (urllib, smtplib) — no requests dependency.
- The upstream `release-check` CI job is disabled (`if: false`) because our
  package.json version (1.0.0-alpha) doesn't match upstream plugin versions.
- CI uses `ubuntu-latest`/`windows-latest` instead of upstream's Blacksmith runners.
- CLAUDE.md and AGENTS.md are separate files (not symlinked like upstream convention).

## Git

- Remote `origin`: tomstetson/declaw (private)
- Remote `upstream`: openclaw/openclaw
- Email: tomstetson@users.noreply.github.com
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`

## Testing Strategy

- Upstream tests via `pnpm test` (vitest)
- DeClaw TypeScript tests colocated: `src/lib/secrets.test.ts`, `src/config/env-substitution.test.ts`,
  `src/lib/declaw-command-policy.test.ts`, `src/lib/declaw-egress-policy.test.ts`,
  `src/lib/declaw-events.test.ts`, `src/lib/declaw-audit.test.ts`,
  `src/lib/declaw-metrics.test.ts`, `src/config/secret-resolution.integration.test.ts`
- Python tool tests: `python3 -m pytest tests/python/ -v` (273 tests)
- Test counts: 189 vitest (41 existing + 148 DeClaw) + 273 pytest = 462 total

## Current State (v1.0.0-alpha)

**Working:** secret:// URI resolution, secrets.ts bridge, all 3 Python tools,
command policy enforcement, egress policy enforcement, webhook alerts (4 providers),
plugin security scanning (policy evaluation, integrity verification, sandbox compat),
unified audit trail (Phase 3: event schema, JSONL logger, instrumented hooks),
in-memory metrics counters, SIEM transport (fire-and-forget HTTP POST),
observability config types, audit CLI (query/export/stats), doctor O1/O2 checks,
Python tools migrated to unified event schema
**Tested e2e:** secret:// URI resolution through full config loading pipeline
