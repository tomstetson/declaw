/**
 * DeClaw Command Policy — Admin-enforced command restrictions.
 *
 * This layer runs BEFORE OpenClaw's user-managed exec-approvals allowlist.
 * Commands denied here cannot be bypassed by user approval. The policy is
 * configured in openclaw.json at `tools.exec.commandPolicy` or per-agent
 * at `agents.list[].tools.exec.commandPolicy`.
 *
 * Modes:
 *   - "off"       — No command restrictions (default, upstream behavior)
 *   - "allowlist"  — Only listed commands may execute
 *   - "denylist"   — Listed commands are blocked, everything else allowed
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DeclawCommandPolicyMode = "off" | "allowlist" | "denylist";

export type DeclawCommandPolicyConfig = {
  /** Policy enforcement mode. */
  mode: DeclawCommandPolicyMode;
  /** Commands allowed when mode is "allowlist". Supports wildcards (*). */
  allow?: string[];
  /** Commands blocked when mode is "denylist". Supports wildcards (*). */
  deny?: string[];
};

export type DeclawCommandPolicyResult = {
  allowed: boolean;
  reason?: string;
  /** The binary name that triggered a deny, if any. */
  deniedBinary?: string;
  /** The policy mode that produced this result. */
  mode: DeclawCommandPolicyMode;
};

// ---------------------------------------------------------------------------
// Shell command parsing
// ---------------------------------------------------------------------------

/**
 * Shell operators that separate commands. We split on these to find
 * all binary names in a compound command like `ls && cat foo | grep bar`.
 */
const SHELL_OPERATORS = /\s*(?:\|\||&&|;;?|\|)\s*/;

/**
 * Extract binary names from a shell command string.
 *
 * Handles common patterns:
 *   - Simple commands: `ls -la`  → ["ls"]
 *   - Pipes: `cat foo | grep bar` → ["cat", "grep"]
 *   - Chains: `cd /tmp && curl http://evil.com` → ["cd", "curl"]
 *   - Subshells: `(wget ...)` → ["wget"]
 *   - Env prefixes: `LANG=C sort` → ["sort"]
 *   - Absolute paths: `/usr/bin/python3 script.py` → ["python3"]
 *
 * Does NOT handle command substitution $(), backticks, or eval.
 * For unparseable commands, returns an empty array which triggers
 * a deny in allowlist mode (fail-closed).
 */
export function extractBinaryNames(command: string): string[] {
  const trimmed = command.trim();
  if (!trimmed) {
    return [];
  }

  const segments = trimmed.split(SHELL_OPERATORS).filter((s) => s.length > 0);
  const binaries: string[] = [];

  for (const segment of segments) {
    const binary = extractFirstBinary(segment.trim());
    if (binary) {
      binaries.push(binary);
    }
  }

  return binaries;
}

/**
 * Extract the binary name from a single command segment.
 * Skips env var assignments (KEY=VALUE) and subshell markers.
 */
function extractFirstBinary(segment: string): string | null {
  // Strip leading subshell markers
  let s = segment.replace(/^[(\s]+/, "").trim();
  if (!s) {
    return null;
  }

  // Skip env var assignments: LANG=C FOO=bar command ...
  const tokens = tokenizeSimple(s);
  let idx = 0;
  while (idx < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx] ?? "")) {
    idx++;
  }

  const rawBinary = tokens[idx];
  if (!rawBinary) {
    return null;
  }

  // Strip quotes
  const unquoted = rawBinary.replace(/^["']|["']$/g, "");

  // Extract basename from absolute/relative paths: /usr/bin/python3 → python3
  const lastSlash = unquoted.lastIndexOf("/");
  return lastSlash >= 0 ? unquoted.slice(lastSlash + 1) : unquoted;
}

/**
 * Minimal tokenizer that splits on whitespace but respects quotes.
 * Good enough for extracting binary names — not a full shell parser.
 */
function tokenizeSimple(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (const ch of input) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      current += ch;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      continue;
    }
    if ((ch === " " || ch === "\t") && !inSingle && !inDouble) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) {
    tokens.push(current);
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/**
 * Match a binary name against a pattern. Supports simple wildcards:
 *   - `*` matches any sequence of characters
 *   - `python*` matches `python3`, `python3.12`
 *   - `*curl*` matches `curl`, `libcurl-tool`
 *   - Exact match: `ls` matches only `ls`
 *
 * Matching is case-insensitive on all platforms for consistency.
 */
export function matchesPattern(binary: string, pattern: string): boolean {
  const b = binary.toLowerCase();
  const p = pattern.toLowerCase();

  if (!p.includes("*")) {
    return b === p;
  }

  // Convert wildcard pattern to regex
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(b);
}

/**
 * Check if a binary name matches any pattern in a list.
 */
function matchesAnyPattern(binary: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesPattern(binary, pattern));
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a shell command against a DeClaw command policy.
 *
 * In "allowlist" mode, every binary in the command must match at least
 * one allow pattern. If the command can't be parsed, it's denied (fail-closed).
 *
 * In "denylist" mode, the command is denied if any binary matches a deny pattern.
 */
export function evaluateDeclawCommandPolicy(
  command: string,
  policy: DeclawCommandPolicyConfig | undefined,
): DeclawCommandPolicyResult {
  if (!policy || policy.mode === "off") {
    return { allowed: true, mode: "off" };
  }

  const binaries = extractBinaryNames(command);

  if (policy.mode === "allowlist") {
    const allowPatterns = policy.allow ?? [];

    // Fail-closed: if we can't parse the command, deny it
    if (binaries.length === 0) {
      return {
        allowed: false,
        reason: "command could not be parsed for allowlist evaluation",
        mode: "allowlist",
      };
    }

    for (const binary of binaries) {
      if (!matchesAnyPattern(binary, allowPatterns)) {
        return {
          allowed: false,
          reason: `binary "${binary}" is not in the command allowlist`,
          deniedBinary: binary,
          mode: "allowlist",
        };
      }
    }

    return { allowed: true, mode: "allowlist" };
  }

  if (policy.mode === "denylist") {
    const denyPatterns = policy.deny ?? [];

    for (const binary of binaries) {
      if (matchesAnyPattern(binary, denyPatterns)) {
        return {
          allowed: false,
          reason: `binary "${binary}" is in the command denylist`,
          deniedBinary: binary,
          mode: "denylist",
        };
      }
    }

    return { allowed: true, mode: "denylist" };
  }

  // Unknown mode — fail-closed
  return {
    allowed: false,
    reason: `unknown command policy mode: ${policy.mode as string}`,
    mode: policy.mode,
  };
}
