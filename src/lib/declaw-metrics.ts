/**
 * DeClaw Metrics — in-memory counters for security events.
 *
 * Auto-incremented by emitDeclawEvent() in declaw-audit.ts.
 * Provides getDeclawMetrics() for health checks and dashboards.
 *
 * Counters are in-memory only — they reset on process restart.
 * For historical data, query ~/.declaw/audit.jsonl via readAuditEvents().
 */

import type { DeclawEventCategory, DeclawSecurityEvent } from "./declaw-events.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DeclawMetrics = {
  /** Per-category event counts. */
  counters: Partial<Record<DeclawEventCategory, number>>;
  /** Total events emitted since process start. */
  total: number;
  /** Events with outcome "failure" or "denied". */
  errors: number;
  /** ISO 8601 timestamp of when tracking started. */
  startedAt: string;
};

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

const counters: Partial<Record<string, number>> = {};
let total = 0;
let errors = 0;
const startedAt = new Date().toISOString();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Increment counters for a security event. Called from emitDeclawEvent(). */
export function incrementDeclawMetrics(event: DeclawSecurityEvent): void {
  counters[event.category] = (counters[event.category] ?? 0) + 1;
  total += 1;
  if (event.outcome === "failure" || event.outcome === "denied") {
    errors += 1;
  }
}

/** Return a snapshot of current metrics. */
export function getDeclawMetrics(): DeclawMetrics {
  return {
    counters: { ...counters } as Partial<Record<DeclawEventCategory, number>>,
    total,
    errors,
    startedAt,
  };
}

/** Reset all counters (for testing). */
export function resetDeclawMetrics(): void {
  for (const key of Object.keys(counters)) {
    delete counters[key];
  }
  total = 0;
  errors = 0;
}
