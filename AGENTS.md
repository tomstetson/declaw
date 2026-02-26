# DeClaw Navigation Guide

Security-hardened fork of OpenClaw. Adds secrets management, config validation,
runtime anomaly detection, and sandbox enforcement to OpenClaw's multi-channel
AI gateway.

## Key Files

| File                                    | Purpose                                             | When to Read                        |
| --------------------------------------- | --------------------------------------------------- | ----------------------------------- |
| `CLAUDE.md`                             | DeClaw project instructions, commands, architecture | First - always                      |
| `CHANGELOG-DECLAW.md`                   | DeClaw-specific changelog and feature inventory     | Understanding what DeClaw adds      |
| `README.md`                             | Public-facing docs with security deep-dive          | Before any README changes           |
| `src/lib/secrets.ts`                    | TypeScript bridge to Python secrets manager         | Modifying secret resolution         |
| `src/lib/secrets.test.ts`               | Tests for secrets.ts                                | After changing secrets.ts           |
| `src/config/env-substitution.ts`        | Config value substitution (secret:// + ${})         | Modifying config loading            |
| `src/config/env-substitution.test.ts`   | Tests for env substitution including secret://      | After changing env-substitution     |
| `scripts/declaw-secrets/declaw-secrets` | Multi-provider secrets manager (Python)             | Secrets bugs or new providers       |
| `scripts/declaw-doctor/declaw-doctor`   | Config security validator (Python)                  | Config validation bugs              |
| `scripts/declaw-monitor/declaw-monitor` | Runtime anomaly detector (Python)                   | Monitoring bugs or new patterns     |
| `src/lib/declaw-command-policy.ts`      | Command allowlist/denylist enforcement (Phase 2)    | Command policy bugs or extensions   |
| `src/lib/declaw-egress-policy.ts`       | Egress filtering for sandbox containers (Phase 2)   | Egress policy bugs or extensions    |
| `src/lib/declaw-plugin-security.ts`     | Plugin security scanning policy (Phase 2)           | Plugin security bugs or extensions  |
| `package.json`                          | DeClaw branding, bin entries, version               | Version bumps or dependency changes |
| `.github/workflows/ci.yml`              | CI config (modified for fork)                       | CI failures                         |

## Patterns

- **DeClaw additions** are isolated from upstream code. TypeScript integration is
  limited to `src/lib/secrets.ts` and a small block in `env-substitution.ts`.
- **Python tools** are standalone scripts with shebangs, not importable modules.
  They communicate via stdout/stderr/exit codes.
- **Upstream files** should not be modified unless required for DeClaw integration.
- **CI** uses `ubuntu-latest` instead of upstream Blacksmith runners.
- **Tests** are colocated vitest files (`*.test.ts`) for TypeScript.

## Common Tasks

| Task                  | Command                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| Run all tests         | `pnpm test`                                                             |
| Run DeClaw tests only | `pnpm test src/lib/secrets.test.ts src/config/env-substitution.test.ts` |
| Type check            | `pnpm tsgo`                                                             |
| Lint + format check   | `pnpm check`                                                            |
| Fix formatting        | `pnpm format:fix`                                                       |
| Test secrets tool     | `python3 scripts/declaw-secrets/declaw-secrets --help`                  |
| Test doctor tool      | `python3 scripts/declaw-doctor/declaw-doctor --help`                    |
| Test monitor tool     | `python3 scripts/declaw-monitor/declaw-monitor --help`                  |

## Directory Structure (DeClaw-Specific)

```
scripts/
  declaw-secrets/     # Secrets manager (668 lines Python)
    declaw-secrets    # Main script
    declaw-secrets-v1 # Legacy v1 (deprecated)
    PROVIDERS.md      # Provider documentation
    TESTING.md        # Test procedures
    setup.py          # Python packaging
  declaw-doctor/      # Config validator (568 lines Python)
    declaw-doctor     # Main script
  declaw-monitor/     # Anomaly detector (526 lines Python)
    declaw-monitor    # Main script
src/
  lib/
    secrets.ts                   # TypeScript secrets bridge (121 lines)
    secrets.test.ts              # Tests
    declaw-command-policy.ts     # Command allowlist/denylist (Phase 2)
    declaw-command-policy.test.ts
    declaw-egress-policy.ts      # Egress filtering (Phase 2)
    declaw-egress-policy.test.ts
    declaw-plugin-security.ts    # Plugin security scanning (Phase 2)
    declaw-plugin-security.test.ts
  config/
    env-substitution.ts          # Modified for secret:// support
    env-substitution.test.ts     # Tests (includes secret:// cases)
    types.tools.ts               # Modified: added commandPolicy to ExecToolConfig
    types.sandbox.ts             # Modified: added egressPolicy to SandboxDockerSettings
    types.plugins.ts             # Modified: added pluginSecurity to PluginsConfig
  agents/
    bash-tools.exec.ts           # Modified: DeClaw command policy hook
    bash-tools.exec-types.ts     # Modified: commandPolicy in ExecToolDefaults
    sandbox/config.ts            # Modified: egress policy enforcement
tests/
  python/
    conftest.py                  # Shared pytest fixtures
    test_declaw_secrets.py       # 45 tests
    test_declaw_doctor.py        # 64 tests (includes Phase 2 checks)
    test_declaw_monitor.py       # 89 tests
```
