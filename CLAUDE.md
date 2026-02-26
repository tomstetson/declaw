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

- `src/lib/secrets.ts` - TypeScript bridge to declaw-secrets (execSync to Python)
- `src/config/env-substitution.ts` - `secret://` URI integration (lines 92-99)
- `scripts/declaw-secrets/` - Multi-provider secrets manager (Python 3.8+)
- `scripts/declaw-doctor/` - Config security validator (Python 3.8+)
- `scripts/declaw-monitor/` - Runtime anomaly detector (Python 3.8+)
- `README.md` - DeClaw-specific README
- `CHANGELOG-DECLAW.md` - DeClaw changelog
- `SECURITY.md` - Security policy (still references upstream, needs updating)

Everything else is upstream OpenClaw. Do not modify upstream files unless
necessary for DeClaw integration.

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

- `secrets.ts` resolves the Python script path relative to `__dirname` via
  `../../scripts/declaw-secrets/declaw-secrets`. This breaks if file moves.
- Python tools are standalone scripts (shebang `#!/usr/bin/env python3`), not
  importable modules. They communicate via stdout/stderr/exit codes.
- `declaw-monitor`'s `_send_alert()` is a stub - webhook alerting not implemented.
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
- DeClaw TypeScript tests colocated: `src/lib/secrets.test.ts`, `src/config/env-substitution.test.ts`
- Python tool tests: `scripts/declaw-secrets/TESTING.md` documents manual test procedures
- No pytest infrastructure yet (planned)

## Current State (v1.0.0-alpha)

**Working:** secret:// URI resolution, secrets.ts bridge, all 3 Python tools standalone
**Not tested:** End-to-end secret resolution through OpenClaw config loading
**Not implemented:** Command allowlist, egress filtering, webhook alerts, plugin scanning
