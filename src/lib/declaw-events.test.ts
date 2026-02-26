import { describe, expect, it } from "vitest";
import type {
  DeclawEventCategory,
  DeclawEventInput,
  DeclawEventOutcome,
  DeclawEventSeverity,
  DeclawSecurityEvent,
} from "./declaw-events.js";

describe("DeclawSecurityEvent schema", () => {
  it("accepts a fully populated event", () => {
    const event: DeclawSecurityEvent = {
      timestamp: "2026-02-26T12:00:00.000Z",
      version: 1,
      source: "declaw-gateway",
      category: "policy.deny",
      severity: "high",
      detail: { binary: "curl", reason: "denylist" },
      outcome: "denied",
      agentId: "agent-1",
      sessionId: "sess-123",
      user: "tom",
      pid: 12345,
      correlationId: "corr-abc",
    };

    expect(event.version).toBe(1);
    expect(event.source).toBe("declaw-gateway");
    expect(event.detail.binary).toBe("curl");
  });

  it("accepts a minimal event (required fields only)", () => {
    const event: DeclawSecurityEvent = {
      timestamp: "2026-02-26T12:00:00.000Z",
      version: 1,
      source: "declaw-secrets",
      category: "secret.access",
      severity: "info",
      detail: { key: "API_KEY" },
      outcome: "success",
    };

    expect(event.agentId).toBeUndefined();
    expect(event.pid).toBeUndefined();
  });

  it("DeclawEventInput omits timestamp, version, and pid", () => {
    const input: DeclawEventInput = {
      source: "declaw-gateway",
      category: "egress.enforce",
      severity: "medium",
      detail: { effectiveNetwork: "none" },
      outcome: "success",
    };

    // These should NOT exist on the input type
    expect("timestamp" in input).toBe(false);
    expect("version" in input).toBe(false);
    expect("pid" in input).toBe(false);
  });

  it("covers all event categories", () => {
    const categories: DeclawEventCategory[] = [
      "secret.access",
      "secret.error",
      "config.check",
      "config.fix",
      "policy.deny",
      "policy.allow",
      "egress.enforce",
      "egress.warning",
      "plugin.scan",
      "plugin.deny",
      "monitor.detection",
      "monitor.kill",
      "monitor.start",
      "audit.export",
    ];
    expect(categories).toHaveLength(14);
  });

  it("covers all severity levels", () => {
    const severities: DeclawEventSeverity[] = ["critical", "high", "medium", "low", "info"];
    expect(severities).toHaveLength(5);
  });

  it("covers all outcomes", () => {
    const outcomes: DeclawEventOutcome[] = ["success", "failure", "denied", "warning"];
    expect(outcomes).toHaveLength(4);
  });
});
