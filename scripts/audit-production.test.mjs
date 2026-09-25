import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAudit } from "./audit-production.mjs";

const advisory = {
  module_name: "@mariozechner/pi-coding-agent",
  github_advisory_id: "GHSA-jfgx-wxx8-mp94",
  severity: "high",
  findings: [{ version: "0.55.0" }],
};
const report = (items) => ({
  advisories: Object.fromEntries(items.map((item, i) => [i, item])),
  metadata: {
    vulnerabilities: {
      high: items.filter((x) => x.severity === "high").length,
      critical: items.filter((x) => x.severity === "critical").length,
    },
  },
});

await test("only the exact reviewed Pi backport can satisfy a high finding", () => {
  assert.deepEqual(evaluateAudit(report([advisory]), true), {
    blocked: [],
    mitigated: ["GHSA-jfgx-wxx8-mp94"],
  });
  assert.equal(evaluateAudit(report([advisory]), false).blocked.length, 1);
  assert.equal(
    evaluateAudit(report([{ ...advisory, github_advisory_id: "GHSA-new-finding" }]), true).blocked
      .length,
    1,
  );
  assert.equal(
    evaluateAudit(report([{ ...advisory, findings: [{ version: "0.56.0" }] }]), true).blocked
      .length,
    1,
  );
  assert.equal(
    evaluateAudit(report([{ ...advisory, severity: "critical" }]), true).blocked.length,
    1,
  );
});

await test("missing or inconsistent scanner output fails closed", () => {
  assert.throws(() => evaluateAudit({}, true));
  const empty = report([]);
  empty.metadata.vulnerabilities.high = 1;
  assert.throws(() => evaluateAudit(empty, true));
  assert.deepEqual(evaluateAudit(report([]), false), { blocked: [], mitigated: [] });
});
