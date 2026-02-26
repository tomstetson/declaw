/**
 * DeClaw Plugin Security — policy evaluation for plugin scanning results.
 *
 * Wraps OpenClaw's existing skill-scanner output and applies DeClaw's
 * security policy: enforce/warn/off modes, capability restrictions,
 * integrity verification, and sandbox compatibility checking.
 *
 * Integration: called from src/plugins/install.ts after the existing
 * skill-scanner runs, and optionally from loader.ts at startup.
 */

import type { SkillScanFinding, SkillScanSummary } from "../security/skill-scanner.js";

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

export type DeclawPluginSecurityConfig = {
  /**
   * "off"     — no enforcement (existing upstream behavior)
   * "warn"    — log warnings but allow install/load
   * "enforce" — block install/load if policy violated
   */
  mode: "off" | "warn" | "enforce";

  /** Max critical findings before blocking (enforce mode). Default: 0. */
  maxCriticalFindings?: number;

  /**
   * Blocked capability categories. Plugins using these capabilities
   * are denied in enforce mode.
   * Categories: "exec", "eval", "network", "env", "crypto-mining"
   */
  blockedCapabilities?: string[];

  /** Require SHA256 integrity checksum file (.sha256). Default: false. */
  requireIntegrity?: boolean;

  /** Plugin origins that skip scanning. Default: ["bundled"]. */
  trustedOrigins?: string[];
};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type DeclawPluginSecurityResult = {
  allowed: boolean;
  mode: string;
  reason: string;
  criticalCount: number;
  warnCount: number;
  capabilityViolations: string[];
  findings: SkillScanFinding[];
};

export type IntegrityCheckResult = {
  valid: boolean;
  checksumFile: string;
  expected?: string;
  actual?: string;
  error?: string;
};

export type SandboxCompatibilityResult = {
  compatible: boolean;
  issues: string[];
};

// ---------------------------------------------------------------------------
// Capability mapping
// ---------------------------------------------------------------------------

/** Map skill-scanner rule IDs to DeClaw capability categories. */
const RULE_TO_CAPABILITY: Record<string, string> = {
  "dangerous-exec": "exec",
  "dynamic-code-execution": "eval",
  "suspicious-network": "network",
  "potential-exfiltration": "network",
  "env-harvesting": "env",
  "crypto-mining": "crypto-mining",
  "websocket-usage": "network",
};

/**
 * Map a skill-scanner rule ID to a DeClaw capability category.
 * Returns undefined if the rule doesn't map to a known capability.
 */
export function findingToCapability(ruleId: string): string | undefined {
  return RULE_TO_CAPABILITY[ruleId];
}

/**
 * Extract the set of capabilities detected in scan findings.
 */
export function extractCapabilities(findings: SkillScanFinding[]): string[] {
  const caps = new Set<string>();
  for (const f of findings) {
    const cap = findingToCapability(f.ruleId);
    if (cap) {
      caps.add(cap);
    }
  }
  return [...caps].toSorted();
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

const DEFAULT_MAX_CRITICAL = 0;
const DEFAULT_TRUSTED_ORIGINS = ["bundled"];

/**
 * Evaluate a plugin's scan results against the DeClaw plugin security policy.
 *
 * @param scanSummary - Output from skill-scanner's scanDirectoryWithSummary()
 * @param policy      - DeClaw plugin security config (from openclaw.json)
 * @param origin      - Plugin origin: "bundled" | "global" | "workspace" | "config"
 * @returns           - Result with allowed/denied, reason, and details
 */
export function evaluatePluginSecurity(
  scanSummary: SkillScanSummary,
  policy?: DeclawPluginSecurityConfig,
  origin?: string,
): DeclawPluginSecurityResult {
  // No policy or off → always allow
  if (!policy || policy.mode === "off") {
    return {
      allowed: true,
      mode: policy?.mode ?? "off",
      reason: "Plugin security policy is off",
      criticalCount: scanSummary.critical,
      warnCount: scanSummary.warn,
      capabilityViolations: [],
      findings: scanSummary.findings,
    };
  }

  // Trusted origins skip enforcement
  const trustedOrigins = policy.trustedOrigins ?? DEFAULT_TRUSTED_ORIGINS;
  if (origin && trustedOrigins.includes(origin)) {
    return {
      allowed: true,
      mode: policy.mode,
      reason: `Plugin origin "${origin}" is trusted`,
      criticalCount: scanSummary.critical,
      warnCount: scanSummary.warn,
      capabilityViolations: [],
      findings: scanSummary.findings,
    };
  }

  const maxCritical = policy.maxCriticalFindings ?? DEFAULT_MAX_CRITICAL;
  const blockedCaps = policy.blockedCapabilities ?? [];
  const violations: string[] = [];

  // Check critical finding count
  const criticalExceeded = scanSummary.critical > maxCritical;

  // Check capability violations
  if (blockedCaps.length > 0) {
    const detected = extractCapabilities(scanSummary.findings);
    for (const cap of detected) {
      if (blockedCaps.includes(cap)) {
        violations.push(cap);
      }
    }
  }

  // Build reason
  const reasons: string[] = [];
  if (criticalExceeded) {
    reasons.push(`${scanSummary.critical} critical finding(s) exceed max ${maxCritical}`);
  }
  if (violations.length > 0) {
    reasons.push(`blocked capabilities detected: ${violations.join(", ")}`);
  }

  const hasViolations = criticalExceeded || violations.length > 0;

  if (policy.mode === "enforce" && hasViolations) {
    return {
      allowed: false,
      mode: "enforce",
      reason: reasons.join("; "),
      criticalCount: scanSummary.critical,
      warnCount: scanSummary.warn,
      capabilityViolations: violations,
      findings: scanSummary.findings,
    };
  }

  // warn mode or no violations
  return {
    allowed: true,
    mode: policy.mode,
    reason: hasViolations ? `Warning: ${reasons.join("; ")}` : "Plugin passed security checks",
    criticalCount: scanSummary.critical,
    warnCount: scanSummary.warn,
    capabilityViolations: violations,
    findings: scanSummary.findings,
  };
}

// ---------------------------------------------------------------------------
// Sandbox compatibility
// ---------------------------------------------------------------------------

type SandboxDockerConfig = {
  network?: string;
  readOnlyRoot?: boolean;
  capDrop?: string[];
};

/**
 * Check if a plugin's detected capabilities are compatible with the
 * sandbox configuration. E.g., a plugin using network capabilities
 * can't work in a network=none sandbox.
 */
export function checkSandboxCompatibility(
  scanSummary: SkillScanSummary,
  sandboxConfig?: SandboxDockerConfig,
): SandboxCompatibilityResult {
  if (!sandboxConfig) {
    return { compatible: true, issues: [] };
  }

  const caps = extractCapabilities(scanSummary.findings);
  const issues: string[] = [];

  // Network: none means no network access
  if (sandboxConfig.network === "none" && caps.includes("network")) {
    issues.push("Plugin uses network capabilities but sandbox has network=none");
  }

  // Exec: capDrop ALL means no spawning child processes
  if (sandboxConfig.capDrop?.includes("ALL") && caps.includes("exec")) {
    issues.push("Plugin uses child_process but sandbox drops ALL capabilities");
  }

  return {
    compatible: issues.length === 0,
    issues,
  };
}

// ---------------------------------------------------------------------------
// Integrity verification
// ---------------------------------------------------------------------------

/**
 * Verify a plugin directory against a SHA256 checksum file.
 *
 * The checksum file format is one line per file:
 *   <sha256hex>  <relative-path>
 *
 * Same format as `sha256sum` output.
 */
export async function verifyPluginIntegrity(
  pluginDir: string,
  checksumFile: string,
): Promise<IntegrityCheckResult> {
  const { createHash } = await import("node:crypto");
  const fs = await import("node:fs/promises");
  const path = await import("node:path");

  try {
    const content = await fs.readFile(checksumFile, "utf-8");
    const lines = content
      .trim()
      .split("\n")
      .filter((l) => l.trim());

    if (lines.length === 0) {
      return {
        valid: false,
        checksumFile,
        error: "Checksum file is empty",
      };
    }

    for (const line of lines) {
      // Format: <hash>  <path> (two spaces between, like sha256sum)
      const match = line.match(/^([a-f0-9]{64})\s{1,2}(.+)$/);
      if (!match) {
        return {
          valid: false,
          checksumFile,
          error: `Invalid checksum line: ${line.slice(0, 80)}`,
        };
      }

      const [, expectedHash, relativePath] = match;

      // Prevent path traversal: resolved path must stay inside pluginDir
      const filePath = path.resolve(pluginDir, relativePath ?? "");
      const resolvedPluginDir = path.resolve(pluginDir);
      if (!filePath.startsWith(resolvedPluginDir + path.sep) && filePath !== resolvedPluginDir) {
        return {
          valid: false,
          checksumFile,
          error: `Path traversal detected in checksum file: ${relativePath}`,
        };
      }

      try {
        const fileContent = await fs.readFile(filePath);
        const actualHash = createHash("sha256").update(fileContent).digest("hex");

        if (actualHash !== expectedHash) {
          return {
            valid: false,
            checksumFile,
            expected: expectedHash,
            actual: actualHash,
            error: `Checksum mismatch for ${relativePath}`,
          };
        }
      } catch {
        return {
          valid: false,
          checksumFile,
          error: `File not found: ${relativePath}`,
        };
      }
    }

    return { valid: true, checksumFile };
  } catch {
    return {
      valid: false,
      checksumFile,
      error: "Checksum file not found or unreadable",
    };
  }
}
