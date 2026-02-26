import { afterEach, describe, expect, it } from "vitest";
import type { DeclawSecurityEvent } from "./declaw-events.js";
import { getDeclawMetrics, incrementDeclawMetrics, resetDeclawMetrics } from "./declaw-metrics.js";

function makeEvent(overrides: Partial<DeclawSecurityEvent> = {}): DeclawSecurityEvent {
  return {
    timestamp: "2026-02-26T12:00:00.000Z",
    version: 1,
    source: "declaw-gateway",
    category: "policy.deny",
    severity: "high",
    detail: {},
    outcome: "denied",
    pid: 1234,
    ...overrides,
  };
}

describe("declaw-metrics", () => {
  afterEach(() => {
    resetDeclawMetrics();
  });

  describe("incrementDeclawMetrics", () => {
    it("increments the correct category counter", () => {
      incrementDeclawMetrics(makeEvent({ category: "policy.deny" }));
      incrementDeclawMetrics(makeEvent({ category: "policy.deny" }));
      incrementDeclawMetrics(makeEvent({ category: "secret.access", outcome: "success" }));

      const m = getDeclawMetrics();
      expect(m.counters["policy.deny"]).toBe(2);
      expect(m.counters["secret.access"]).toBe(1);
    });

    it("increments total on every call", () => {
      incrementDeclawMetrics(makeEvent({ category: "policy.deny" }));
      incrementDeclawMetrics(makeEvent({ category: "secret.access", outcome: "success" }));
      incrementDeclawMetrics(makeEvent({ category: "egress.enforce", outcome: "success" }));

      expect(getDeclawMetrics().total).toBe(3);
    });

    it("increments errors for failure outcome", () => {
      incrementDeclawMetrics(makeEvent({ outcome: "failure" }));
      incrementDeclawMetrics(makeEvent({ outcome: "success" }));

      expect(getDeclawMetrics().errors).toBe(1);
    });

    it("increments errors for denied outcome", () => {
      incrementDeclawMetrics(makeEvent({ outcome: "denied" }));
      incrementDeclawMetrics(makeEvent({ outcome: "warning" }));

      expect(getDeclawMetrics().errors).toBe(1);
    });

    it("does not increment errors for success or warning", () => {
      incrementDeclawMetrics(makeEvent({ outcome: "success" }));
      incrementDeclawMetrics(makeEvent({ outcome: "warning" }));

      expect(getDeclawMetrics().errors).toBe(0);
    });
  });

  describe("getDeclawMetrics", () => {
    it("returns a snapshot (not a reference to internal state)", () => {
      incrementDeclawMetrics(makeEvent());
      const snapshot1 = getDeclawMetrics();
      incrementDeclawMetrics(makeEvent());
      const snapshot2 = getDeclawMetrics();

      expect(snapshot1.total).toBe(1);
      expect(snapshot2.total).toBe(2);
    });

    it("has a valid ISO 8601 startedAt timestamp", () => {
      const m = getDeclawMetrics();
      expect(() => new Date(m.startedAt)).not.toThrow();
      expect(new Date(m.startedAt).toISOString()).toBe(m.startedAt);
    });

    it("returns zero counters before any events", () => {
      const m = getDeclawMetrics();
      expect(m.total).toBe(0);
      expect(m.errors).toBe(0);
      expect(Object.keys(m.counters)).toHaveLength(0);
    });
  });

  describe("resetDeclawMetrics", () => {
    it("clears all counters", () => {
      incrementDeclawMetrics(makeEvent({ category: "policy.deny" }));
      incrementDeclawMetrics(makeEvent({ category: "secret.access", outcome: "success" }));
      resetDeclawMetrics();

      const m = getDeclawMetrics();
      expect(m.total).toBe(0);
      expect(m.errors).toBe(0);
      expect(Object.keys(m.counters)).toHaveLength(0);
    });
  });
});
