import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { getChildLogger, isFileLogLevelEnabled, resetLogger, setLoggerOverride } from "./logger.js";

let directory: string;
beforeEach(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), "declaw-log-level-"));
  vi.stubEnv("OPENCLAW_LOG_LEVEL", "");
});
afterEach(() => {
  resetLogger();
  setLoggerOverride(null);
  vi.unstubAllEnvs();
  fs.rmSync(directory, { recursive: true, force: true });
});

it("trace includes ordinary messages and warn retains errors without verbose messages", () => {
  for (const level of ["trace", "warn"] as const) {
    const file = path.join(directory, `${level}.log`);
    setLoggerOverride({ level, file });
    const logger = getChildLogger({ module: "threshold-test" });
    logger.trace("trace-marker");
    logger.info("info-marker");
    logger.warn("warn-marker");
    logger.error("error-marker");
    logger.fatal("fatal-marker");
    const output = fs.readFileSync(file, "utf8");
    expect(output).toContain("warn-marker");
    expect(output).toContain("error-marker");
    expect(output).toContain("fatal-marker");
    expect(output.includes("trace-marker")).toBe(level === "trace");
    expect(output.includes("info-marker")).toBe(level === "trace");
    expect(isFileLogLevelEnabled("error")).toBe(true);
    expect(isFileLogLevelEnabled("debug")).toBe(level === "trace");
  }
});
