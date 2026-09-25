import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  configureSiemTransport,
  emitDeclawEvent,
  readAuditEvents,
  resetAuditLogPath,
  resetSiemTransport,
  setAuditLogPath,
} from "./declaw-audit.js";
import type { DeclawSecurityEvent } from "./declaw-events.js";

describe("declaw-audit", () => {
  let tmpDir: string;
  let auditFile: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "declaw-audit-test-"));
    auditFile = path.join(tmpDir, "audit.jsonl");
    setAuditLogPath(auditFile);
  });

  afterEach(() => {
    resetAuditLogPath();
    resetSiemTransport();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // -- emitDeclawEvent ---------------------------------------------------

  describe("emitDeclawEvent", () => {
    it("writes a JSONL line to the audit file", () => {
      emitDeclawEvent({
        source: "declaw-gateway",
        category: "policy.deny",
        severity: "high",
        detail: { binary: "curl", reason: "denylist" },
        outcome: "denied",
      });

      const content = fs.readFileSync(auditFile, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(1);

      const event = JSON.parse(lines[0]) as DeclawSecurityEvent;
      expect(event.version).toBe(1);
      expect(event.source).toBe("declaw-gateway");
      expect(event.category).toBe("policy.deny");
      expect(event.severity).toBe("high");
      expect(event.detail.binary).toBe("curl");
      expect(event.outcome).toBe("denied");
      expect(event.pid).toBe(process.pid);
      expect(event.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it("appends multiple events to the same file", () => {
      emitDeclawEvent({
        source: "declaw-gateway",
        category: "secret.access",
        severity: "info",
        detail: { key: "KEY_A" },
        outcome: "success",
      });
      emitDeclawEvent({
        source: "declaw-gateway",
        category: "secret.access",
        severity: "info",
        detail: { key: "KEY_B" },
        outcome: "success",
      });

      const content = fs.readFileSync(auditFile, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(2);
    });

    it("enriches events with timestamp, version, and pid", () => {
      emitDeclawEvent({
        source: "declaw-gateway",
        category: "egress.enforce",
        severity: "medium",
        detail: { effectiveNetwork: "none" },
        outcome: "success",
      });

      const content = fs.readFileSync(auditFile, "utf-8");
      const event = JSON.parse(content.trim()) as DeclawSecurityEvent;
      expect(event.version).toBe(1);
      expect(event.pid).toBeTypeOf("number");
      expect(new Date(event.timestamp).getTime()).toBeGreaterThan(0);
    });

    it("preserves optional fields when provided", () => {
      emitDeclawEvent({
        source: "declaw-gateway",
        category: "monitor.kill",
        severity: "critical",
        detail: { pattern: "REVERSE_SHELL" },
        outcome: "success",
        agentId: "agent-42",
        sessionId: "sess-abc",
        correlationId: "corr-xyz",
      });

      const content = fs.readFileSync(auditFile, "utf-8");
      const event = JSON.parse(content.trim()) as DeclawSecurityEvent;
      expect(event.agentId).toBe("agent-42");
      expect(event.sessionId).toBe("sess-abc");
      expect(event.correlationId).toBe("corr-xyz");
    });

    it("creates the audit directory if it does not exist", () => {
      const nestedDir = path.join(tmpDir, "nested", "deep");
      setAuditLogPath(path.join(nestedDir, "audit.jsonl"));

      emitDeclawEvent({
        source: "declaw-gateway",
        category: "config.check",
        severity: "low",
        detail: { checkId: "L1" },
        outcome: "success",
      });

      expect(fs.existsSync(path.join(nestedDir, "audit.jsonl"))).toBe(true);
    });

    it("does not throw when audit file is unwritable", () => {
      // A regular file cannot be a parent directory on any supported platform.
      // Recursive mkdir beneath Linux /proc can loop instead of returning an error.
      const blockedParent = path.join(tmpDir, "not-a-directory");
      fs.writeFileSync(blockedParent, "preserve this file");
      setAuditLogPath(path.join(blockedParent, "audit.jsonl"));

      // Should not throw — audit logging is best-effort
      expect(() =>
        emitDeclawEvent({
          source: "declaw-gateway",
          category: "secret.error",
          severity: "high",
          detail: { key: "MISSING" },
          outcome: "failure",
        }),
      ).not.toThrow();
      expect(fs.readFileSync(blockedParent, "utf-8")).toBe("preserve this file");
    });
  });

  // -- readAuditEvents ---------------------------------------------------

  describe("readAuditEvents", () => {
    function writeEvents(events: DeclawSecurityEvent[]): void {
      const content = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
      fs.writeFileSync(auditFile, content);
    }

    const baseEvent: DeclawSecurityEvent = {
      timestamp: "2026-02-26T10:00:00.000Z",
      version: 1,
      source: "declaw-gateway",
      category: "policy.deny",
      severity: "high",
      detail: { binary: "curl" },
      outcome: "denied",
    };

    it("reads all events from the audit file", () => {
      writeEvents([
        { ...baseEvent, timestamp: "2026-02-26T10:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-26T11:00:00.000Z" },
      ]);

      const events = readAuditEvents();
      expect(events).toHaveLength(2);
    });

    it("returns events newest first", () => {
      writeEvents([
        { ...baseEvent, timestamp: "2026-02-26T10:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-26T12:00:00.000Z" },
      ]);

      const events = readAuditEvents();
      expect(events[0].timestamp).toBe("2026-02-26T12:00:00.000Z");
      expect(events[1].timestamp).toBe("2026-02-26T10:00:00.000Z");
    });

    it("filters by category", () => {
      writeEvents([
        { ...baseEvent, category: "policy.deny" },
        { ...baseEvent, category: "secret.access", severity: "info", outcome: "success" },
        { ...baseEvent, category: "policy.deny" },
      ]);

      const events = readAuditEvents({ categories: ["secret.access"] });
      expect(events).toHaveLength(1);
      expect(events[0].category).toBe("secret.access");
    });

    it("filters by severity", () => {
      writeEvents([
        { ...baseEvent, severity: "critical" },
        { ...baseEvent, severity: "high" },
        { ...baseEvent, severity: "info" },
      ]);

      const events = readAuditEvents({ severities: ["critical", "high"] });
      expect(events).toHaveLength(2);
    });

    it("filters by since date", () => {
      writeEvents([
        { ...baseEvent, timestamp: "2026-02-25T10:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-26T10:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-27T10:00:00.000Z" },
      ]);

      const events = readAuditEvents({ since: new Date("2026-02-26T00:00:00.000Z") });
      expect(events).toHaveLength(2);
    });

    it("respects limit", () => {
      writeEvents([
        { ...baseEvent, timestamp: "2026-02-26T10:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-26T11:00:00.000Z" },
        { ...baseEvent, timestamp: "2026-02-26T12:00:00.000Z" },
      ]);

      const events = readAuditEvents({ limit: 2 });
      expect(events).toHaveLength(2);
      // Newest first
      expect(events[0].timestamp).toBe("2026-02-26T12:00:00.000Z");
    });

    it("returns empty array for missing file", () => {
      setAuditLogPath(path.join(tmpDir, "nonexistent.jsonl"));
      const events = readAuditEvents();
      expect(events).toEqual([]);
    });

    it("returns empty array for empty file", () => {
      fs.writeFileSync(auditFile, "");
      const events = readAuditEvents();
      expect(events).toEqual([]);
    });
  });

  // -- SIEM transport ------------------------------------------------------

  describe("configureSiemTransport", () => {
    it("accepts null to disable", () => {
      expect(() => configureSiemTransport(null)).not.toThrow();
    });

    it("accepts a valid config", () => {
      expect(() =>
        configureSiemTransport({
          enabled: true,
          endpoint: "https://siem.example.com/events",
        }),
      ).not.toThrow();
    });

    it("does not throw when emitting with SIEM disabled", () => {
      configureSiemTransport({ enabled: false, endpoint: "https://example.com" });
      expect(() =>
        emitDeclawEvent({
          source: "declaw-gateway",
          category: "policy.deny",
          severity: "high",
          detail: {},
          outcome: "denied",
        }),
      ).not.toThrow();
    });

    it("does not throw when SIEM endpoint is unreachable", () => {
      configureSiemTransport({
        enabled: true,
        endpoint: "http://127.0.0.1:1",
        timeoutMs: 100,
      });
      expect(() =>
        emitDeclawEvent({
          source: "declaw-gateway",
          category: "policy.deny",
          severity: "high",
          detail: {},
          outcome: "denied",
        }),
      ).not.toThrow();
    });

    it("does not forward when endpoint is empty", () => {
      configureSiemTransport({ enabled: true, endpoint: "" });
      // Should not throw even with enabled + empty endpoint
      expect(() =>
        emitDeclawEvent({
          source: "declaw-gateway",
          category: "secret.access",
          severity: "info",
          detail: {},
          outcome: "success",
        }),
      ).not.toThrow();
    });
  });
});
