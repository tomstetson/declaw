import { spawnSync } from "node:child_process";

// Respect a user's security hooks, including a globally configured hooksPath.
// Package preparation must never replace them with repository-local hooks.
const inside = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { stdio: "ignore" });
if (inside.status === 0) {
  const configured = spawnSync("git", ["config", "--get", "core.hooksPath"], { encoding: "utf8" });
  if (configured.status === 1) {
    const installed = spawnSync("git", ["config", "core.hooksPath", "git-hooks"], {
      stdio: "inherit",
    });
    if (installed.status !== 0) {
      throw new Error("Could not install repository Git hooks");
    }
  } else if (configured.status !== 0) {
    throw new Error("Could not inspect existing Git hook configuration");
  }
}
