/**
 * DeClaw Security Event Schema — canonical event type for all DeClaw audit events.
 *
 * Used by both TypeScript gateway code and Python tools (mirrored in
 * scripts/declaw-common/event_schema.py). All DeClaw security events share
 * this shape and are written to ~/.declaw/audit.jsonl.
 *
 * Design: Flat with a `detail` bag (ECS-inspired). Enables SIEM queries like
 * `source="declaw-*" severity="critical" category="policy.deny"` without
 * deep JSON path traversal.
 *
 * See docs/adr/004-unified-observability.md for rationale.
 */

// ---------------------------------------------------------------------------
// Event categories
// ---------------------------------------------------------------------------

export type DeclawEventCategory =
  | "secret.access" // Secret retrieved from vault
  | "secret.error" // Secret resolution failed
  | "config.check" // Doctor check result
  | "config.fix" // Doctor auto-fix applied
  | "policy.deny" // Command policy denied a binary
  | "policy.allow" // Command policy allowed (debug-level)
  | "egress.enforce" // Egress policy applied
  | "egress.warning" // Egress policy produced a warning
  | "plugin.scan" // Plugin security scan result
  | "plugin.deny" // Plugin blocked by policy
  | "monitor.detection" // Anomaly detection triggered
  | "monitor.kill" // Kill switch activated
  | "monitor.start" // Monitor daemon started
  | "audit.export"; // Audit trail exported

// ---------------------------------------------------------------------------
// Event severity
// ---------------------------------------------------------------------------

export type DeclawEventSeverity = "critical" | "high" | "medium" | "low" | "info";

// ---------------------------------------------------------------------------
// Event outcome
// ---------------------------------------------------------------------------

export type DeclawEventOutcome = "success" | "failure" | "denied" | "warning";

// ---------------------------------------------------------------------------
// Core event type
// ---------------------------------------------------------------------------

export type DeclawSecurityEvent = {
  /** ISO 8601 timestamp. Added automatically by emitDeclawEvent. */
  timestamp: string;
  /** Schema version for forward compatibility. */
  version: 1;
  /** Which DeClaw component emitted this event. */
  source: "declaw-secrets" | "declaw-doctor" | "declaw-monitor" | "declaw-gateway";
  /** Event category — what happened. */
  category: DeclawEventCategory;
  /** Event severity. */
  severity: DeclawEventSeverity;
  /** Category-specific payload. */
  detail: Record<string, unknown>;
  /** What was the result. */
  outcome: DeclawEventOutcome;
  /** Agent that triggered this event (if applicable). */
  agentId?: string;
  /** Session context (if applicable). */
  sessionId?: string;
  /** OS user. */
  user?: string;
  /** Process ID. */
  pid?: number;
  /** Correlation ID for linking related events (e.g., startup sequence). */
  correlationId?: string;
};

// ---------------------------------------------------------------------------
// Input type (timestamp/version/pid added by emitDeclawEvent)
// ---------------------------------------------------------------------------

export type DeclawEventInput = Omit<DeclawSecurityEvent, "timestamp" | "version" | "pid">;
