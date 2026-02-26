/**
 * DeClaw Audit Logger — unified security event emission.
 *
 * Central point for all DeClaw security events in the TypeScript gateway.
 * Events are:
 *   1. Written to ~/.declaw/audit.jsonl (append-only JSONL)
 *   2. Logged via OpenClaw's subsystem logger ("declaw") for file + console
 *
 * Python tools write to the same audit.jsonl file directly using the
 * shared event schema (scripts/declaw-common/event_schema.py).
 *
 * See docs/adr/004-unified-observability.md for architecture details.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";
import type { DeclawEventInput, DeclawSecurityEvent } from "./declaw-events.js";
import { incrementDeclawMetrics } from "./declaw-metrics.js";

// ---------------------------------------------------------------------------
// Subsystem logger (routes to OpenClaw's file + console logging)
// ---------------------------------------------------------------------------

const log = createSubsystemLogger("declaw");

// ---------------------------------------------------------------------------
// Audit file path
// ---------------------------------------------------------------------------

const DECLAW_DIR = path.join(os.homedir(), ".declaw");
const DEFAULT_AUDIT_PATH = path.join(DECLAW_DIR, "audit.jsonl");

let auditFilePath = DEFAULT_AUDIT_PATH;
let auditDirReady = false;

/**
 * Override the audit log path (useful for testing or custom config).
 * Must be called before any events are emitted.
 */
export function setAuditLogPath(filePath: string): void {
  auditFilePath = filePath;
  auditDirReady = false;
}

/** Reset to default path (for testing). */
export function resetAuditLogPath(): void {
  auditFilePath = DEFAULT_AUDIT_PATH;
  auditDirReady = false;
}

// ---------------------------------------------------------------------------
// File writer (append-only, atomic for lines < PIPE_BUF)
// ---------------------------------------------------------------------------

function ensureAuditDir(): void {
  if (auditDirReady) {
    return;
  }
  try {
    const dir = path.dirname(auditFilePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    auditDirReady = true;
  } catch {
    // Best-effort — if we can't create the dir, events still go to the logger
  }
}

function appendAuditEntry(event: DeclawSecurityEvent): void {
  ensureAuditDir();
  try {
    const line = JSON.stringify(event) + "\n";
    fs.appendFileSync(auditFilePath, line, { mode: 0o600 });
  } catch {
    // Audit logging is best-effort. If the file write fails, the event
    // is still logged via the subsystem logger above.
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Emit a DeClaw security event.
 *
 * Enriches the event with timestamp, version, and PID, then:
 *   1. Appends to ~/.declaw/audit.jsonl
 *   2. Logs via the "declaw" subsystem logger
 */
export function emitDeclawEvent(input: DeclawEventInput): void {
  const event: DeclawSecurityEvent = {
    ...input,
    timestamp: new Date().toISOString(),
    version: 1,
    pid: process.pid,
  };

  // Write to audit file
  appendAuditEntry(event);

  // Increment in-memory metrics counters
  incrementDeclawMetrics(event);

  // Log via subsystem logger (appears in OpenClaw's log files and console)
  const message = `${event.category}: ${formatDetail(event)}`;
  const meta = { declawEvent: event };

  switch (event.severity) {
    case "critical":
    case "high":
      log.warn(message, meta);
      break;
    case "medium":
    case "low":
      log.info(message, meta);
      break;
    case "info":
      log.debug(message, meta);
      break;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function d(val: unknown): string {
  if (val === null || val === undefined) {
    return "";
  }
  return typeof val === "string" ? val : JSON.stringify(val);
}

function formatDetail(event: DeclawSecurityEvent): string {
  const { category, outcome, detail } = event;
  // Produce a human-readable summary for console/file logging
  switch (category) {
    case "secret.access":
      return `resolved secret "${d(detail.key)}" at ${d(detail.configPath)} [${outcome}]`;
    case "secret.error":
      return `failed to resolve secret "${d(detail.key)}" at ${d(detail.configPath)}: ${d(detail.error)}`;
    case "policy.deny":
      return `denied command "${d(detail.binary)}" (${d(detail.reason)}) [${d(detail.mode)}]`;
    case "policy.allow":
      return `allowed command "${d(detail.binary)}" [${d(detail.mode)}]`;
    case "egress.enforce":
      return `enforced egress policy → network=${d(detail.effectiveNetwork)} [${outcome}]`;
    case "egress.warning":
      return `egress warning: ${d(detail.message)}`;
    case "config.check":
      return `check ${d(detail.checkId)}: ${d(detail.title)} [${outcome}]`;
    case "config.fix":
      return `auto-fixed ${d(detail.checkId)}: ${d(detail.title)}`;
    case "plugin.scan":
      return `scanned plugin "${d(detail.pluginId)}" → ${outcome}`;
    case "plugin.deny":
      return `blocked plugin "${d(detail.pluginId)}": ${d(detail.reason)}`;
    case "monitor.detection":
      return `detected ${d(detail.pattern)} (${event.severity}) in agent ${event.agentId ?? "unknown"}`;
    case "monitor.kill":
      return `killed container for agent ${event.agentId ?? "unknown"}: ${d(detail.pattern)}`;
    default:
      return JSON.stringify(detail);
  }
}

// ---------------------------------------------------------------------------
// Read API (for compliance queries)
// ---------------------------------------------------------------------------

/**
 * Read audit events from the audit log file.
 * Returns parsed events, newest first.
 */
export function readAuditEvents(opts?: {
  limit?: number;
  categories?: string[];
  severities?: string[];
  since?: Date;
}): DeclawSecurityEvent[] {
  try {
    const content = fs.readFileSync(auditFilePath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);
    let events: DeclawSecurityEvent[] = lines.map(
      (line) => JSON.parse(line) as DeclawSecurityEvent,
    );

    // Filter
    if (opts?.categories?.length) {
      events = events.filter((e) => opts.categories!.includes(e.category));
    }
    if (opts?.severities?.length) {
      events = events.filter((e) => opts.severities!.includes(e.severity));
    }
    if (opts?.since) {
      const sinceMs = opts.since.getTime();
      events = events.filter((e) => new Date(e.timestamp).getTime() >= sinceMs);
    }

    // Newest first
    events.reverse();

    // Limit
    if (opts?.limit && opts.limit > 0) {
      events = events.slice(0, opts.limit);
    }

    return events;
  } catch {
    return [];
  }
}
