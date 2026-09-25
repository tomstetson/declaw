# Standalone dependency maintenance — 2026-09-25

Workspace overrides do not follow an extension when the plugin installer copies
its directory and runs npm independently. The UI and Zalo manifests now declare
Vite 7.3.6 and Undici 7.29.1, matching the patched workspace resolutions.
Diagnostics now declares the matching OpenTelemetry 0.222.0 API/logging/exporter
family and SDK Node; the stable SDK packages remain on 2.11.0.

An isolated npm install with only SDK Node updated still resolved the old OTLP
transformer's exact protobufjs 8.0.0 dependency: one critical, six high and five
moderate audit entries. Updating the exporter family removes that obsolete
branch. Fresh standalone lock resolutions for diagnostics, Zalo and the UI each
report zero vulnerabilities. This also fixes the standalone old-core baggage
allocation and Prometheus exporter findings. The pnpm lock was regenerated;
the root overrides remain useful for other workspace consumers.

The new log processor accepts one options object. Keeping its old positional
constructor silently dropped buffered records and failed shutdown. The caller
now uses the supported API, explicitly retaining the previous 5000 ms default
flush delay and the existing 1000 ms minimum for configured intervals. Three
configuration controls and a real SDK buffered-export/shutdown regression failed
before the adaptation and pass afterwards. The real processor test substitutes
an in-memory exporter, so it sends no telemetry to an external collector.

Verification: 37 focused Zalo/telemetry tests, full type/lint/format checks, UI
build, real NodeSDK start/shutdown with exporters disabled, and the production
audit gate pass. The root audit still reports the previously documented Pi
backport's one high/two low version entries and two moderate findings; this
follow-up does not relabel the whole repository as advisory-free.

To reproduce, use the committed pnpm lock, run `pnpm check`, `pnpm --dir ui build`
and the focused extension tests. In three disposable directories, copy each
subpackage's package.json, run `npm install --package-lock-only --ignore-scripts`
and `npm audit --json`; do not rely on root overrides for that check. Existing
published upstream plugin packages are not republished by merging this fork.
Future locally packed or fork-published extensions must carry these manifests.

Rollback requires reverting the family update, lock and processor adaptation
together. Reverting only the caller or only the SDK breaks log export. Restoring
the old standalone versions also restores known vulnerabilities.
