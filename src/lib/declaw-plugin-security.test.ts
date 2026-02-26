import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeEach, afterEach } from "vitest";
import type { SkillScanFinding, SkillScanSummary } from "../security/skill-scanner.js";
import {
  evaluatePluginSecurity,
  extractCapabilities,
  findingToCapability,
  checkSandboxCompatibility,
  verifyPluginIntegrity,
  type DeclawPluginSecurityConfig,
} from "./declaw-plugin-security.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(
  ruleId: string,
  severity: "critical" | "warn" | "info" = "critical",
): SkillScanFinding {
  return {
    ruleId,
    severity,
    file: "index.ts",
    line: 1,
    message: `Detected ${ruleId}`,
    evidence: "test evidence",
  };
}

function makeSummary(findings: SkillScanFinding[] = []): SkillScanSummary {
  return {
    scannedFiles: 5,
    critical: findings.filter((f) => f.severity === "critical").length,
    warn: findings.filter((f) => f.severity === "warn").length,
    info: findings.filter((f) => f.severity === "info").length,
    findings,
  };
}

// ---------------------------------------------------------------------------
// findingToCapability
// ---------------------------------------------------------------------------

describe("findingToCapability", () => {
  it("maps dangerous-exec to exec", () => {
    expect(findingToCapability("dangerous-exec")).toBe("exec");
  });

  it("maps dynamic-code-execution to eval", () => {
    expect(findingToCapability("dynamic-code-execution")).toBe("eval");
  });

  it("maps suspicious-network to network", () => {
    expect(findingToCapability("suspicious-network")).toBe("network");
  });

  it("maps potential-exfiltration to network", () => {
    expect(findingToCapability("potential-exfiltration")).toBe("network");
  });

  it("maps env-harvesting to env", () => {
    expect(findingToCapability("env-harvesting")).toBe("env");
  });

  it("maps crypto-mining to crypto-mining", () => {
    expect(findingToCapability("crypto-mining")).toBe("crypto-mining");
  });

  it("returns undefined for unknown rule", () => {
    expect(findingToCapability("unknown-rule")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractCapabilities
// ---------------------------------------------------------------------------

describe("extractCapabilities", () => {
  it("returns empty array for no findings", () => {
    expect(extractCapabilities([])).toEqual([]);
  });

  it("extracts unique capabilities sorted", () => {
    const findings = [
      makeFinding("dangerous-exec"),
      makeFinding("suspicious-network"),
      makeFinding("potential-exfiltration"), // also "network" — deduped
    ];
    expect(extractCapabilities(findings)).toEqual(["exec", "network"]);
  });

  it("skips findings with no capability mapping", () => {
    const findings = [makeFinding("obfuscated-code"), makeFinding("dangerous-exec")];
    expect(extractCapabilities(findings)).toEqual(["exec"]);
  });
});

// ---------------------------------------------------------------------------
// evaluatePluginSecurity
// ---------------------------------------------------------------------------

describe("evaluatePluginSecurity", () => {
  const cleanSummary = makeSummary([]);

  describe("mode: off", () => {
    it("allows everything when mode is off", () => {
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, { mode: "off" });
      expect(result.allowed).toBe(true);
      expect(result.mode).toBe("off");
    });

    it("allows everything when no policy provided", () => {
      const result = evaluatePluginSecurity(cleanSummary);
      expect(result.allowed).toBe(true);
    });

    it("allows everything when policy is undefined", () => {
      const result = evaluatePluginSecurity(cleanSummary, undefined);
      expect(result.allowed).toBe(true);
    });
  });

  describe("trusted origins", () => {
    const policy: DeclawPluginSecurityConfig = {
      mode: "enforce",
      maxCriticalFindings: 0,
    };

    it("allows bundled plugins by default even with critical findings", () => {
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy, "bundled");
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("trusted");
    });

    it("does not trust global origin by default", () => {
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy, "global");
      expect(result.allowed).toBe(false);
    });

    it("respects custom trusted origins", () => {
      const customPolicy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        trustedOrigins: ["bundled", "global"],
      };
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, customPolicy, "global");
      expect(result.allowed).toBe(true);
    });
  });

  describe("mode: enforce", () => {
    it("blocks when critical findings exceed max (default 0)", () => {
      const policy: DeclawPluginSecurityConfig = { mode: "enforce" };
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("critical finding");
    });

    it("allows when critical findings within custom max", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        maxCriticalFindings: 2,
      };
      const summary = makeSummary([
        makeFinding("dangerous-exec"),
        makeFinding("dynamic-code-execution"),
      ]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(true);
    });

    it("blocks when critical findings exceed custom max", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        maxCriticalFindings: 1,
      };
      const summary = makeSummary([
        makeFinding("dangerous-exec"),
        makeFinding("dynamic-code-execution"),
      ]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(false);
    });

    it("blocks on capability violations", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        maxCriticalFindings: 99, // allow critical
        blockedCapabilities: ["network"],
      };
      const summary = makeSummary([makeFinding("suspicious-network", "warn")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(false);
      expect(result.capabilityViolations).toEqual(["network"]);
      expect(result.reason).toContain("blocked capabilities");
    });

    it("allows when no blocked capabilities match", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        blockedCapabilities: ["crypto-mining"],
      };
      const summary = makeSummary([makeFinding("suspicious-network", "warn")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(true);
    });

    it("allows clean plugin in enforce mode", () => {
      const policy: DeclawPluginSecurityConfig = { mode: "enforce" };
      const result = evaluatePluginSecurity(cleanSummary, policy);
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("passed");
    });

    it("combines critical and capability reasons", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "enforce",
        blockedCapabilities: ["exec"],
      };
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("critical");
      expect(result.reason).toContain("exec");
    });
  });

  describe("mode: warn", () => {
    it("allows even with critical findings", () => {
      const policy: DeclawPluginSecurityConfig = { mode: "warn" };
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("Warning");
    });

    it("allows with capability violations but includes warning", () => {
      const policy: DeclawPluginSecurityConfig = {
        mode: "warn",
        blockedCapabilities: ["exec"],
      };
      const summary = makeSummary([makeFinding("dangerous-exec")]);
      const result = evaluatePluginSecurity(summary, policy);
      expect(result.allowed).toBe(true);
      expect(result.capabilityViolations).toEqual(["exec"]);
    });

    it("passes cleanly with no issues", () => {
      const policy: DeclawPluginSecurityConfig = { mode: "warn" };
      const result = evaluatePluginSecurity(cleanSummary, policy);
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("passed");
    });
  });

  describe("result fields", () => {
    it("includes finding counts", () => {
      const summary = makeSummary([
        makeFinding("dangerous-exec", "critical"),
        makeFinding("suspicious-network", "warn"),
        makeFinding("obfuscated-code", "info"),
      ]);
      const result = evaluatePluginSecurity(summary, { mode: "warn" });
      expect(result.criticalCount).toBe(1);
      expect(result.warnCount).toBe(1);
    });

    it("passes through findings array", () => {
      const findings = [makeFinding("dangerous-exec")];
      const summary = makeSummary(findings);
      const result = evaluatePluginSecurity(summary, { mode: "warn" });
      expect(result.findings).toBe(summary.findings);
    });
  });
});

// ---------------------------------------------------------------------------
// checkSandboxCompatibility
// ---------------------------------------------------------------------------

describe("checkSandboxCompatibility", () => {
  it("returns compatible when no sandbox config", () => {
    const summary = makeSummary([makeFinding("suspicious-network")]);
    const result = checkSandboxCompatibility(summary);
    expect(result.compatible).toBe(true);
    expect(result.issues).toEqual([]);
  });

  it("flags network plugin with network=none sandbox", () => {
    const summary = makeSummary([makeFinding("suspicious-network", "warn")]);
    const result = checkSandboxCompatibility(summary, { network: "none" });
    expect(result.compatible).toBe(false);
    expect(result.issues[0]).toContain("network");
  });

  it("allows network plugin with bridge sandbox", () => {
    const summary = makeSummary([makeFinding("suspicious-network", "warn")]);
    const result = checkSandboxCompatibility(summary, { network: "bridge" });
    expect(result.compatible).toBe(true);
  });

  it("flags exec plugin with capDrop ALL", () => {
    const summary = makeSummary([makeFinding("dangerous-exec")]);
    const result = checkSandboxCompatibility(summary, {
      capDrop: ["ALL"],
    });
    expect(result.compatible).toBe(false);
    expect(result.issues[0]).toContain("child_process");
  });

  it("allows exec plugin without capDrop", () => {
    const summary = makeSummary([makeFinding("dangerous-exec")]);
    const result = checkSandboxCompatibility(summary, { capDrop: [] });
    expect(result.compatible).toBe(true);
  });

  it("returns compatible for clean scan", () => {
    const summary = makeSummary([]);
    const result = checkSandboxCompatibility(summary, {
      network: "none",
      capDrop: ["ALL"],
    });
    expect(result.compatible).toBe(true);
  });

  it("reports multiple issues", () => {
    const summary = makeSummary([
      makeFinding("suspicious-network", "warn"),
      makeFinding("dangerous-exec"),
    ]);
    const result = checkSandboxCompatibility(summary, {
      network: "none",
      capDrop: ["ALL"],
    });
    expect(result.compatible).toBe(false);
    expect(result.issues).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// verifyPluginIntegrity
// ---------------------------------------------------------------------------

describe("verifyPluginIntegrity", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "declaw-plugin-test-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("returns valid when checksums match", async () => {
    const content = "console.log('hello');";
    await fs.writeFile(path.join(tmpDir, "index.js"), content);

    const hash = createHash("sha256").update(content).digest("hex");
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${hash}  index.js\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(true);
  });

  it("returns invalid when checksums mismatch", async () => {
    await fs.writeFile(path.join(tmpDir, "index.js"), "original");

    const fakeHash = "a".repeat(64);
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${fakeHash}  index.js\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("mismatch");
    expect(result.expected).toBe(fakeHash);
  });

  it("returns invalid when referenced file missing", async () => {
    const hash = "b".repeat(64);
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${hash}  missing.js\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("not found");
  });

  it("returns invalid when checksum file missing", async () => {
    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "nonexistent.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("not found");
  });

  it("returns invalid for empty checksum file", async () => {
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), "\n");

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("empty");
  });

  it("returns invalid for malformed checksum line", async () => {
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), "not-a-valid-checksum-line\n");

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Invalid checksum line");
  });

  it("validates multiple files", async () => {
    const file1 = "file one content";
    const file2 = "file two content";
    await fs.writeFile(path.join(tmpDir, "a.js"), file1);
    await fs.writeFile(path.join(tmpDir, "b.js"), file2);

    const hash1 = createHash("sha256").update(file1).digest("hex");
    const hash2 = createHash("sha256").update(file2).digest("hex");
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${hash1}  a.js\n${hash2}  b.js\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(true);
  });

  it("rejects path traversal in checksum file", async () => {
    // A malicious checksum file could reference ../../etc/passwd to trick
    // the integrity check into reading files outside the plugin directory.
    const fakeHash = "a".repeat(64);
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${fakeHash}  ../../etc/passwd\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Path traversal");
  });

  it("rejects absolute path in checksum file", async () => {
    const fakeHash = "b".repeat(64);
    await fs.writeFile(path.join(tmpDir, "plugin.sha256"), `${fakeHash}  /etc/passwd\n`);

    const result = await verifyPluginIntegrity(tmpDir, path.join(tmpDir, "plugin.sha256"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Path traversal");
  });
});
