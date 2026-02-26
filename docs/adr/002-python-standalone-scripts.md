---
status: accepted
date: 2026-02-10
---

# ADR-002: Python Standalone Scripts for Security Tools

## Status

Accepted

## Context

DeClaw adds three security tools: a secrets manager, a config validator, and a
runtime anomaly detector. These tools need to:

- Call external CLIs (`security`, `vault`, `bw`, `op`, `docker`)
- Parse JSON config files and JSONL transcripts
- Run as both standalone commands and subprocess callouts from Node
- Be auditable (users should be able to read the source for security review)
- Add zero npm dependencies to the OpenClaw dependency tree

The project is primarily TypeScript (OpenClaw), so the language choice requires
justification.

## Decision

Implement all three tools as standalone Python scripts with shebangs
(`#!/usr/bin/env python3`), using only Python standard library modules. They
live in `scripts/declaw-*/` and communicate with the TypeScript layer via
stdout, stderr, and exit codes.

- **declaw-secrets** (668 lines): Multi-provider secrets manager. Abstract
  `SecretProvider` base class with 5 implementations.
- **declaw-doctor** (568 lines): Config security validator. 10 checks with
  auto-fix support.
- **declaw-monitor** (526 lines): Runtime anomaly detector. 10 regex-based
  detection patterns with kill switch.

TypeScript integration is limited to `src/lib/secrets.ts`, which calls
`declaw-secrets` via `execSync`. The other two tools are invoked directly by
users or by future startup hooks.

## Consequences

**Positive:**

- Zero npm dependencies added. Python stdlib provides subprocess, json, re,
  pathlib, getpass, argparse -- everything needed.
- Directly executable via npm bin entries (shebang works without compilation).
- Readable source for security auditing (no transpilation or bundling).
- Each tool is independently testable outside the Node ecosystem.
- No build step required (Python scripts ship as-is in the npm package).
- Subprocess invocation is idiomatic for CLI wrapping (security, vault, bw, op,
  docker are all CLI tools -- Python subprocess-to-subprocess is natural).

**Negative:**

- Language fragmentation: project now requires both TypeScript and Python
  knowledge for maintenance.
- Python interpreter cold start adds ~200-300ms per invocation. Acceptable for
  startup operations, not suitable for hot-path usage.
- No compile-time type safety in Python scripts. Relying on runtime validation
  and tests to catch type errors.
- Different error handling models (TypeScript exceptions vs Python
  exceptions/exit codes) require careful alignment at the bridge layer.
- Deployment requires Python 3.8+ alongside Node 22+. Standard on Linux/macOS
  but adds a dependency for Windows environments.

## Alternatives Considered

**Rewrite all three in TypeScript**
Rejected. Would require npm packages for keychain access (node-keytar, native
binding with platform builds), Docker interaction, and file watching. Adds
dependency surface, build complexity, and version-lock concerns with no
functional benefit.

**Secrets manager only in TypeScript, others in Python**
Rejected. Inconsistent language split creates higher maintenance burden than
all-or-nothing. The three tools share design patterns (CLI argument parsing,
JSON config handling, audit logging) that benefit from consistency.

**Node.js sidecar daemon for secrets**
Rejected. Added operational overhead (another long-running process), HTTP API
attack surface, and npm dependency licensing review -- all for startup-only
operations.

**Python as importable modules instead of scripts**
Rejected. Scripts enforce process isolation (separate memory space, separate
crash domain). Importable modules would require a Python package manager
(pip/poetry) and blur the boundary between the TypeScript and Python layers.
