---
status: accepted
date: 2026-02-25
---

# ADR-003: Clean Rebuild Fork Strategy

## Status

Accepted

## Context

DeClaw is a security-hardened fork of OpenClaw. It modifies two upstream files
(`src/config/env-substitution.ts`, `package.json`) and adds new files
(`src/lib/secrets.ts`, `scripts/declaw-*/`, `README.md`, etc.). OpenClaw
releases roughly every 1-2 weeks with 50-200 commits per release.

The fork must balance:

- Staying current with upstream security and feature improvements
- Keeping DeClaw-specific changes clearly identifiable
- Minimizing merge conflict burden on a one-person maintenance team
- Enabling clean rollback if an upstream release breaks DeClaw

## Decision

Use a clean rebuild strategy: start each DeClaw release from a tagged upstream
release, then re-apply DeClaw-specific changes on top.

Process:

1. Save all DeClaw-specific files to a temporary location
2. Reset the branch to the target upstream tag (e.g., `v2026.2.24`)
3. Re-apply DeClaw changes, adapting to any upstream refactors
4. Verify: `pnpm tsgo` (types), `pnpm check` (lint/format), `pnpm test` (tests)
5. Force-push as new main

DeClaw tracks upstream via a second remote (`upstream` pointing to
`openclaw/openclaw`). Between rebuilds, critical upstream security fixes can
be cherry-picked individually.

## Consequences

**Positive:**

- Clean commit history: DeClaw main shows only DeClaw commits on top of a
  known upstream tag. Easy to audit what DeClaw changes.
- No merge commit noise or interleaved upstream history.
- Each rebuild forces explicit review of upstream changes that affect DeClaw
  integration points (env-substitution.ts being the primary one).
- Version independence: DeClaw `1.0.0-alpha` is clearly separate from upstream
  `2026.2.24`.
- Simple mental model: "DeClaw = OpenClaw tag + these N files changed/added."

**Negative:**

- Manual effort per upstream release: must save DeClaw files, checkout new tag,
  re-apply changes, fix any conflicts from upstream refactors. Takes 30-60min
  depending on upstream changes.
- Falls behind upstream between rebuilds. If upstream patches a CVE on Monday
  and DeClaw rebuilds on Friday, there is a 4-day exposure window.
- Force-push required: rewrites main branch history, which breaks anyone
  else's local clone (acceptable for a single-maintainer private repo).
- No incremental cherry-picks visible in history: if upstream made 200 commits,
  DeClaw shows 1 rebuild commit. Granular attribution to upstream changes is
  lost.
- `git blame` on upstream files shows the rebuild commit, not the original
  upstream author.

## Alternatives Considered

**Traditional merge-based fork**
Rejected. OpenClaw's 50-200 commits per release would dominate DeClaw's
history, making it hard to see what DeClaw adds. Merge conflicts on
`env-substitution.ts` would be frequent since upstream actively refactors
config loading.

**Git subtree merge**
Rejected. Complex workflow, error-prone commands, poor IDE/tool support.
Appropriate for vendoring a library, not for forking a full application.

**Patch queue (quilt-style)**
Considered but not chosen. Would maintain DeClaw changes as a series of `.patch`
files applied to each upstream release. Clean in theory, but patch conflicts
on upstream refactors require manual resolution (same effort as rebuild) and
the tooling is less familiar.

**Wrapper approach (OpenClaw as npm dependency)**
Rejected. DeClaw modifies `env-substitution.ts` at the source level -- this
cannot be achieved by wrapping or extending OpenClaw's public API. Would
require upstream to expose plugin hooks that do not exist.

**Automated sync GitHub Action**
Future enhancement, not current practice. Could detect new upstream releases
and open a PR with the rebuild applied. Blocked on having enough test coverage
to validate the rebuild automatically (in progress via ADR-001/002 testing
strategy).
