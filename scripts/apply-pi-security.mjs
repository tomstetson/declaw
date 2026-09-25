// Portable equivalent of the pnpm Pi 0.55.0 patch for npm/global installs.
// Verify every source and destination before changing any dependency file.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
import crypto from "node:crypto";
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.resolve("@mariozechner/pi-coding-agent"))),
  "..",
);
const bundle = path.join(scriptDirectory, "..", "vendor", "pi-security-backport");
const version = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version;
if (version !== "0.55.0") {
  throw new Error("Pi security backport requires reviewed version 0.55.0");
}
const manifest = JSON.parse(fs.readFileSync(path.join(bundle, "manifest.json"), "utf8"));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const changes = Object.entries(manifest).map(([name, expected]) => {
  if (path.isAbsolute(name) || name.split("/").includes("..")) {
    throw new Error("Invalid backport path");
  }
  const target = path.join(root, name);
  const replacement = fs.readFileSync(path.join(bundle, name));
  const current = hash(fs.readFileSync(target));
  if (
    hash(replacement) !== expected.after ||
    ![expected.before, expected.after].includes(current)
  ) {
    throw new Error("Pi backport checksum mismatch: " + name);
  }
  return { target, replacement, applied: current === expected.after };
});
for (const change of changes) {
  if (change.applied) {
    continue;
  }
  const temporary = change.target + ".declaw-security.tmp";
  fs.writeFileSync(temporary, change.replacement, {
    flag: "wx",
    mode: fs.statSync(change.target).mode & 0o777,
  });
  fs.renameSync(temporary, change.target);
  fs.rmSync(change.target + ".map", { force: true });
}
console.log("Pi 0.55.0 security backport verified");
