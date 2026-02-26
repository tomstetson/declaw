---
status: accepted
date: 2026-02-26
author: Claude Code + Human Review
supersedes: null
superseded_by: null
tags: [architecture, observability, logging, metrics, compliance]
---

# ADR-004: Unified DeClaw Observability Architecture

## Status

**Current:** accepted

**Date:** 2026-02-26

**Decision made by:** Claude Code + Human Review

## Context

### Problem Statement

DeClaw's three security tools each write their own log format to separate files:

- `declaw-secrets` writes JSONL to `~/.declaw/audit.log` (secret access events)
- `declaw-monitor` writes JSONL to `~/.declaw/monitor-audit.log` (detection events)
- `declaw-doctor` writes formatted text to stdout (check results)

TypeScript-side DeClaw hooks (`bash-tools.exec.ts`, `sandbox/config.ts`) log security
events as plain strings via `logInfo`/`logWarn`. There are no metrics, no queryable audit
trail, and no way to export events to external systems (SIEM, log aggregators).

An operator running DeClaw in production cannot answer basic questions ("how many commands
were denied this week?", "when was this secret last accessed?") without manual grep across
multiple files with incompatible schemas.

### Requirements

- Unified event schema across TypeScript and Python components
- Single append-only audit log file for all DeClaw security events
- Queryable/exportable audit trail for compliance (SOC2 audit export)
- Metrics counters for security-relevant operations
- SIEM integration without requiring complex infrastructure
- Zero new runtime dependencies

### Constraints

- Python tools are standalone scripts (shebang, not importable modules) — they cannot
  share a TypeScript event bus directly
- OpenClaw's existing logging infrastructure (`tslog`, `registerLogTransport`,
  `emitDiagnosticEvent`) should be extended, not replaced
- Both the gateway process and Python subprocesses may write to the audit log concurrently
- Upstream OpenClaw already has `DiagnosticsOtelConfig` with traces/metrics/logs fields —
  DeClaw's approach should not conflict with upstream's OTel direction

### Assumptions

- Audit log lines will always be under 4096 bytes (POSIX `PIPE_BUF`), making append writes
  atomic without explicit locking
- The primary SIEM deployment model is a local agent (Splunk UF, Filebeat) tailing a log
  file, not direct HTTP push
- Prometheus scraping is the most common metrics collection pattern for self-hosted deployments

## Decision

### What We Will Do

1. **Unified event schema** — Define a canonical `DeclawSecurityEvent` type in TypeScript
   (`src/lib/declaw-events.ts`) and a matching Python helper (`scripts/declaw-common/event_schema.py`).
   Flat structure with a `detail` bag for category-specific payload.

2. **Single audit log** — All DeClaw events (TS and Python) write to `~/.declaw/audit.jsonl`.
   Old per-tool files become symlinks during migration, then are removed in v1.2.

3. **Structured event emission in TypeScript** — Replace plain-string `logInfo`/`logWarn` calls
   in DeClaw hooks with `emitDeclawEvent()`, which writes to the audit log, emits through
   OpenClaw's diagnostic event system, and logs via a `createSubsystemLogger("declaw")` instance.

4. **In-memory metrics counters** — Track secret resolutions, policy denials, egress enforcements,
   plugin scans, and monitor detections. Expose via `declaw metrics` CLI and optionally via a
   `/metrics` Prometheus endpoint on the gateway.

5. **Compliance query/export** — `declaw audit list|export|stats` CLI commands to filter, query,
   and export the audit trail in JSONL, CSV, or syslog RFC 5424 format.

6. **SIEM transport** — Use OpenClaw's `registerLogTransport()` hook to forward DeClaw events
   to syslog, HTTP endpoints (Splunk HEC), or a dedicated file path for log agent pickup.

7. **Config schema** — Add `declaw.auditLogPath`, `declaw.siem`, `declaw.metrics` to
   `OpenClawConfig` via a new `DeclawObservabilityConfig` type.

### What We Will NOT Do

- **No OTel SDK dependency** — Upstream is building toward OTel natively. We produce
  OTel-compatible event shapes but do not bundle the OTel SDK. When upstream ships OTel
  integration, DeClaw events will flow through it automatically.
- **No custom event bus** — We use OpenClaw's existing diagnostic event infrastructure
  rather than building a parallel pub/sub system.
- **No PDF report generation yet** — CSV and JSONL export cover the compliance use case.
  PDF generation (planned for v1.2) is presentation-layer work that can be deferred.
- **No real-time dashboard** — Metrics are pull-based (Prometheus scrape or CLI query),
  not push-based websocket streams.

### Implementation Notes

**Event schema shape:**

```
timestamp | version | source | category | severity | detail | outcome | agentId? | sessionId? | pid?
```

Categories: `secret.access`, `secret.error`, `config.check`, `config.fix`, `policy.deny`,
`policy.allow`, `egress.enforce`, `plugin.scan`, `plugin.deny`, `monitor.detection`,
`monitor.kill`, `audit.export`

The flat-with-detail-bag design follows ECS (Elastic Common Schema) conventions. SIEM queries
like `source="declaw-*" severity="critical" category="policy.deny"` work without deep JSON
path traversal.

**File contention mitigation:**
The gateway process and Python subprocesses (invoked via `execSync`) both append to
`audit.jsonl`. On POSIX, writes under `PIPE_BUF` (4096 bytes) to a file opened with
`O_APPEND` are atomic. All DeClaw events are single-line JSONL well under this limit.

**Python shared module:**
`scripts/declaw-common/event_schema.py` is a single file imported via `sys.path` manipulation
in each Python tool. This avoids packaging complexity while keeping the schema DRY.

## Consequences

### Positive Consequences

- Single file to monitor, ship, and query for all DeClaw security events
- Structured events enable Splunk/ELK/Grafana dashboards without custom parsers
- Compliance audit export covers SOC2 audit trail requirements
- Metrics provide visibility into DeClaw's operational impact (latency, denial rates)
- `registerLogTransport` integration means future OpenClaw logging improvements benefit DeClaw

### Negative Consequences

- Migration period where both old and new audit files exist (symlinks)
- Python tools gain a shared dependency (`event_schema.py`) that must stay in sync with
  the TypeScript type definition
- Prometheus endpoint adds a small HTTP surface to the gateway (opt-in, disabled by default)

### Risks

- Schema evolution: If the event schema changes, old audit entries become harder to query.
  Mitigated by the `version` field — consumers can handle schema versions independently.
- Audit log growth: A busy deployment could generate large audit files.
  Mitigated by configurable rotation (`auditLogMaxBytes`) and retention (`auditLogRetentionDays`).

### Impact

- **Performance:** Negligible — structured logging adds ~0.1ms per event vs plain string.
  Metrics counters are in-memory atomic increments.
- **Security:** Positive — audit trail provides forensic evidence, SIEM integration enables
  real-time alerting on security events.
- **Maintainability:** Positive — unified schema is simpler than three separate formats.
  One place to update when adding new event categories.
- **Developer Experience:** Positive — `emitDeclawEvent()` is a single function call vs
  constructing log strings manually.

## Alternatives Considered

### Alternative 1: OpenTelemetry SDK Integration

**Description:** Bundle the `@opentelemetry/sdk-node` package and emit events as OTel spans,
metrics, and logs directly.

**Pros:**

- Industry standard, wide ecosystem support
- Native integration with Jaeger, Grafana Tempo, etc.

**Cons:**

- Adds ~5MB of dependencies (violates zero-dependency constraint)
- OpenClaw upstream is already building toward OTel — our integration would conflict
- Overkill for a security audit trail (OTel is designed for distributed tracing)

**Why rejected:** Upstream will ship OTel natively. Our job is to produce well-structured
events that flow through it when available, not to ship our own OTel stack.

### Alternative 2: Per-Tool Structured Logging (Keep Separate Files)

**Description:** Standardize the schema across tools but keep separate log files
(`audit.log`, `monitor-audit.log`, `doctor-audit.log`).

**Pros:**

- No migration needed
- Each tool's logs are isolated

**Cons:**

- Operators must configure SIEM agents for 3+ files
- Cross-tool correlation requires joining across files
- Compliance export needs to merge multiple sources

**Why rejected:** A unified audit trail is fundamentally simpler for operators and for
compliance queries. The migration cost is minimal (symlinks during transition).

### Alternative 3: Do Nothing

**Description:** Continue with current plain-string logging and per-tool audit files.

**Pros:**

- No implementation cost
- No migration risk

**Cons:**

- No metrics visibility
- No compliance export capability
- SIEM integration requires custom parsers for each tool's format
- Cannot answer operational questions about DeClaw's security posture

**Why rejected:** Observability is table stakes for production security tooling. Without it,
operators are flying blind on whether DeClaw is actually protecting their deployment.

## References

### Related ADRs

- ADR-001: Secret URI scheme (events will track secret access)
- ADR-002: Python standalone scripts (affects how Python tools emit events)

### Research

- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) — event schema inspiration
- [Prometheus Exposition Format](https://prometheus.io/docs/instrumenting/exposition_formats/) — metrics endpoint format
- [RFC 5424 Syslog](https://datatracker.ietf.org/doc/html/rfc5424) — SIEM export format

## Implementation Checklist

- [ ] Create event schema (TS + Python)
- [ ] Create audit logger (`emitDeclawEvent`)
- [ ] Instrument existing DeClaw hooks
- [ ] Implement metrics counters
- [ ] Migrate Python tools to unified schema
- [ ] Implement compliance query/export CLI
- [ ] Implement SIEM transport
- [ ] Add config schema
- [ ] Tests for all new modules
- [ ] Doctor checks for observability config
- [ ] Update ARCHITECTURE.md with observability diagram
- [ ] Update CHANGELOG-DECLAW.md

## Success Metrics

- All DeClaw security events appear in `~/.declaw/audit.jsonl` with consistent schema
- `declaw audit list --severity critical --since 24h` returns results within 100ms for 90-day logs
- `declaw audit export --format csv` produces SOC2-ingestible output
- Prometheus `/metrics` endpoint returns all counters within 10ms
- Zero regression in existing test suites

---

## Change Log

- 2026-02-26: Created by Claude Code + Human Review
