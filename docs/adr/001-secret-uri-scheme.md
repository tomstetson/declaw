---
status: accepted
date: 2026-02-10
---

# ADR-001: secret:// URI Scheme for Secrets Management

## Status

Accepted

## Context

OpenClaw stores API keys and credentials as plaintext environment variables
(`${ANTHROPIC_API_KEY}` in config). These are visible to any process running as
the same user, appear in `/proc/<pid>/environ`, and are frequently logged by
accident. DeClaw needs a way to resolve secrets from secure vaults without
changing OpenClaw's config format or breaking existing `${}` env var substitution.

Requirements:

- Must integrate into OpenClaw's existing config loading pipeline
- Must support multiple vault backends (macOS Keychain, HashiCorp Vault,
  Bitwarden, 1Password) without adding npm dependencies
- Must be backward-compatible (existing `${}` configs still work)
- Must fail loudly if a secret is missing (no silent fallback to empty string)

## Decision

Introduce a `secret://SECRET_NAME` URI scheme for config values. When
`substituteString()` in `env-substitution.ts` encounters a value starting with
`secret://`, it delegates to `src/lib/secrets.ts`, which calls the Python
`declaw-secrets` script via `execSync` with a 5-second timeout.

The check runs before `${}` env var parsing, so `secret://` takes priority
when a value is an exact match. Partial embedding (e.g.,
`"prefix-secret://KEY"`) is not supported by design -- secrets must be the
entire config value.

Provider selection uses auto-detection (keychain > vault > bitwarden >
1password > env file) or explicit `--provider` flag. Each provider implements
`get()`, `set()`, `list_keys()`, and `is_available()`.

## Consequences

**Positive:**

- Zero npm dependencies for vault integration (Python stdlib handles all providers)
- Auto-detection means zero config for macOS users (Keychain just works)
- Audit logging (`~/.declaw/audit.log` JSONL) provides forensic trail
- Clear error messages: `SecretNotFoundError` tells user exactly what to run
- Backward-compatible: `${}` env vars still work alongside `secret://`

**Negative:**

- `execSync` blocks the Node event loop for up to 5s per secret resolution.
  Acceptable at startup (one-time config load) but would be a bottleneck if
  secrets were resolved per-request.
- Requires Python 3.8+ on the host. Standard on Linux/macOS but not guaranteed
  on Windows without WSL.
- Script path resolution (`../../scripts/declaw-secrets/declaw-secrets` relative
  to `__dirname`) is brittle -- breaks if source files are reorganized.
- No in-memory caching by design (security trade-off: prevents stale secrets,
  but means every config reload calls Python again).
- Error detection parses stderr strings ("not found", "does not exist") which
  is fragile across provider versions.

## Alternatives Considered

**Environment variables only (status quo)**
Rejected. Defeats the core security goal. Env vars are visible to all
processes, logged in crash dumps, and trivially exfiltrated.

**Native Node.js vault clients (node-vault, keytar)**
Rejected. Would add npm dependencies with native bindings (platform-specific
builds), version-lock to specific vault client versions, and require separate
packages for each provider. Python subprocess approach is dependency-free and
delegates version management to the user's installed CLI tools.

**Sidecar secrets server (HTTP API)**
Rejected. Adds operational complexity (another process to manage), introduces
network-level attack surface, and provides no advantage over direct CLI
invocation for a startup-only operation.

**Encrypted local file**
Rejected. Requires its own key management, which just moves the secret storage
problem. Delegating to OS keystores (Keychain) or dedicated vault products is
more secure and auditable.
