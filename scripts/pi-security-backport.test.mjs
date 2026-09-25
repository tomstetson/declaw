import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
const dist = path.dirname(fileURLToPath(import.meta.resolve("@mariozechner/pi-coding-agent")));
const { DefaultPackageManager } = await import(
  pathToFileURL(path.join(dist, "core/package-manager.js"))
);
const { FileAuthStorageBackend } = await import(
  pathToFileURL(path.join(dist, "core/auth-storage.js"))
);
const { parseGitUrl } = await import(pathToFileURL(path.join(dist, "utils/git.js")));

await test("extension cache is private and every git install scope rejects escape", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-security-"));
  try {
    const agentDir = path.join(root, "agent");
    const manager = new DefaultPackageManager({ cwd: root, agentDir, settingsManager: {} });
    const cache = manager.getTemporaryDir("npm");
    assert.ok(cache.startsWith(path.join(agentDir, "tmp", "extensions") + path.sep));
    assert.equal(fs.statSync(path.join(agentDir, "tmp", "extensions")).mode & 0o777, 0o700);
    for (const scope of ["user", "project", "temporary"]) {
      assert.throws(
        () =>
          manager.getGitInstallPath(
            { host: "example.com", path: "../../../../../../outside" },
            scope,
          ),
        /outside package install root/,
      );
      const ordinary = manager.getGitInstallPath(
        { host: "example.com", path: "owner/repo" },
        scope,
      );
      assert.ok(ordinary.startsWith(root + path.sep));
    }
    assert.ok(
      manager
        .getNpmInstallPath({ name: "@scope/extension" }, "temporary")
        .startsWith(cache + path.sep),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

await test("git aliases reject raw, encoded and Windows path traversal", () => {
  for (const source of [
    "git:git@example.com:../../owner/repo",
    "git:git@example.com:owner/%2e%2e/repo",
    "git:git@example.com:owner/%5csecret/repo",
    "git:git@example.com:/absolute/repo",
    "git:example.com/owner/%00repo",
    "git:example.com/owner/%zz",
  ]) {
    assert.equal(parseGitUrl(source), null, source);
  }
  for (const source of [
    "git:github.com/owner/repo",
    "https://github.com/owner/repo",
    "ssh://git@example.com/owner/repo",
    "git:git@example.com:owner/repo@v1",
  ]) {
    const parsed = parseGitUrl(source);
    assert.ok(parsed, source);
    assert.equal(parsed.path, "owner/repo", source);
  }
});

await test("all auth file creation paths set mode before exposing credential bytes", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-auth-security-"));
  const authPath = path.join(root, "auth.json");
  const original = fs.writeFileSync;
  const modes = [];
  const mask = process.umask(0);
  fs.writeFileSync = function (file, data, options) {
    if (file === authPath) {
      modes.push(options?.mode);
    }
    return original.call(this, file, data, options);
  };
  syncBuiltinESMExports();
  try {
    const backend = new FileAuthStorageBackend(authPath);
    backend.withLock(() => ({ result: null, next: "{}" }));
    await backend.withLockAsync(async () => ({ result: null, next: "{}" }));
    assert.equal(modes.length, 3);
    assert.deepEqual(modes, [0o600, 0o600, 0o600]);
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);
  } finally {
    fs.writeFileSync = original;
    syncBuiltinESMExports();
    process.umask(mask);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
