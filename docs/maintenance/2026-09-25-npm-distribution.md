# npm distribution dependency boundary — 2026-09-25

## Outcome: blocked npm release; supported source checkout patched

The pnpm workspace and independently installed UI/Zalo/telemetry manifests were
patched in PRs #1 and #2. This does **not** attest the root npm consumer graph.
The public npm registry returned 404 for `declaw` on September 25, 2026. The README
now directs users to the frozen pnpm source checkout and its production audit gate;
the previously advertised `npm install -g declaw@latest` route was not a published
release of this fork. The source startup command now directly invokes its built CLI.

## Reproduction and disposition

An actual unbundled tarball, installed into an empty npm consumer with no overrides,
resolved eleven high and one critical package-level findings (the extra high is
the consumer's aggregate DeClaw dependency). The independent root manifest alone
reported ten high and one critical. Affected branches include Carbon's Hono server
and ws pins, plus tar 6 under cmake-js and the optional Discord native Opus installer.
Built dist files retain external imports; this is not merely unused lockfile data.

The root Pi 0.55.0 finding is separately mitigated by the shipped exact-hash
postinstall backport. These tarball probes used `--ignore-scripts`; their raw Pi
finding therefore remains visible. This mitigation does not cover the other npm
branches, and installing with scripts enabled is not a fix for those branches.

A disposable production shrinkwrap generated with the reviewed workspace overrides
resolved only the known Pi finding. However, the actual packed consumer still
installed vulnerable versions, even when the shrinkwrap was explicitly included.
The npm 10 local-tarball shrinkwrap limitation is documented upstream, and npm 12
ignores published shrinkwraps entirely. The unsuccessful prototype is **not**
committed as a security fix.

Upstream-only bumps also do not currently close every branch: Carbon 0.16.0 still
pins ws 8.20.0, and @discordjs/opus 0.10.0 / node-pre-gyp 0.4.5 still require tar 6.
Updating node-llama-cpp changes native binaries and requires its own compatibility
validation. A complete npm release needs a reviewed bundling or upstream/fork
strategy, covering platform-native dependencies as well as transitive JS packages.
No npm release or native app publication was performed in this patch round.

## Required release checks

1. Produce the final release tarball with its intended production dependency tree.
2. Install that artifact into empty npm consumers on supported Node/npm/platform
   combinations, without consumer-supplied overrides; enumerate installed files.
3. Audit the actual graph and verify every Pi backport copy by hash and executable
   boundary tests. Unknown audit results must block release.
4. Verify CLI startup, Discord voice/native Opus, local llama loading, archive
   extraction, and legitimate platform fallbacks. A clean workspace audit alone
   is insufficient.
5. Publish only after the packed consumer has no unmitigated high/critical findings.

Sources: [npm current lockfile policy](https://github.com/npm/cli/blob/latest/docs/lib/content/configuring-npm/package-lock-json.md),
[npm local shrinkwrap limitation](https://github.com/npm/cli/issues/5325), and
[npm override scope](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#overrides).
