import { spawnSync } from "node:child_process";
// Version scanners cannot recognize our reviewed Pi source backport. Keep the
// raw result visible and accept only that exact advisory after executable proof.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function evaluateAudit(report, backportVerified) {
  const counts = report?.metadata?.vulnerabilities;
  if (
    !report?.advisories ||
    !counts ||
    !Number.isInteger(counts.high) ||
    !Number.isInteger(counts.critical)
  ) {
    throw new Error("Missing audit data; refusing to accept an incomplete scan");
  }
  const advisories = Object.values(report.advisories);
  for (const severity of ["high", "critical"]) {
    if (advisories.filter((item) => item.severity === severity).length !== counts[severity]) {
      throw new Error("Audit severity totals disagree with advisory records");
    }
  }
  const blocked = [];
  const mitigated = [];
  for (const item of advisories) {
    if (!["high", "critical"].includes(item.severity)) {
      continue;
    }
    const reviewed =
      backportVerified &&
      item.severity === "high" &&
      item.module_name === "@mariozechner/pi-coding-agent" &&
      item.github_advisory_id === "GHSA-jfgx-wxx8-mp94" &&
      item.findings?.length > 0 &&
      item.findings.every((finding) => finding.version === "0.55.0");
    (reviewed ? mitigated : blocked).push(item.github_advisory_id ?? item.module_name);
  }
  return { blocked, mitigated };
}

export function verifyBackport(root) {
  const bundle = path.join(root, "vendor/pi-security-backport");
  const manifest = JSON.parse(fs.readFileSync(path.join(bundle, "manifest.json"), "utf8"));
  const expectedFiles = [
    "dist/core/package-manager.js",
    "dist/utils/git.js",
    "dist/core/auth-storage.js",
    "dist/core/export-html/template.js",
  ];
  if (Object.keys(manifest).toSorted().join() !== expectedFiles.toSorted().join()) {
    throw new Error("Unexpected backport manifest");
  }
  const installations = new Set([
    fs.realpathSync(path.join(root, "node_modules/@mariozechner/pi-coding-agent")),
  ]);
  // Inspect reachable workspace dependencies, not stale pnpm store entries.
  const graph = spawnSync(
    "pnpm",
    ["list", "@mariozechner/pi-coding-agent", "--depth", "Infinity", "--recursive", "--json"],
    { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  if (graph.status !== 0) {
    throw new Error("Cannot enumerate installed Pi dependencies");
  }
  const walk = (value) => {
    if (!value || typeof value !== "object") {
      return;
    }
    for (const [name, child] of Object.entries(value)) {
      if (name === "@mariozechner/pi-coding-agent") {
        if (typeof child?.path !== "string") {
          throw new Error("Pi dependency has no installed path");
        }
        installations.add(fs.realpathSync(child.path));
      }
      walk(child);
    }
  };
  walk(JSON.parse(graph.stdout));
  const hash = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  for (const installation of installations) {
    if (
      JSON.parse(fs.readFileSync(path.join(installation, "package.json"), "utf8")).version !==
      "0.55.0"
    ) {
      throw new Error("Unexpected installed Pi version");
    }
    for (const [file, expected] of Object.entries(manifest)) {
      if (
        hash(path.join(bundle, file)) !== expected.after ||
        hash(path.join(installation, file)) !== expected.after
      ) {
        throw new Error("Unpatched or modified Pi file: " + file);
      }
    }
  }
  const proof = spawnSync(process.execPath, ["--test", "scripts/pi-security-backport.test.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
  if (proof.status !== 0) {
    throw new Error("Pi executable boundary checks failed\n" + proof.stdout + proof.stderr);
  }
  return true;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const scan = spawnSync("pnpm", ["audit", "--prod", "--json"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (![0, 1].includes(scan.status)) {
    throw new Error("Production audit could not complete: " + scan.stderr);
  }
  const report = JSON.parse(scan.stdout);
  console.log("Raw version-based vulnerabilities:", report.metadata?.vulnerabilities);
  const verified = verifyBackport(root);
  const result = evaluateAudit(report, verified);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.blocked.length ? 1 : 0;
}
