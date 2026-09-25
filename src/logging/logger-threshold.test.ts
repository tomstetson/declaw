import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  getChildLogger,
  isFileLogLevelEnabled,
  registerLogTransport,
  resetLogger,
  setLoggerOverride,
} from "./logger.js";

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

it("silent loggers and children neither write nor warn during construction", () => {
  vi.stubEnv("NODE_ENV", "test");
  const file = path.join(directory, "silent.log");
  const warnings = vi.spyOn(console, "warn").mockImplementation(() => {});
  const transport = vi.fn();
  const unregister = registerLogTransport(transport);
  try {
    setLoggerOverride({ level: "silent", file });
    const logger = getChildLogger({ module: "silent-test" });
    logger.fatal("silent-marker");
    logger.getSubLogger({ name: "nested" }).fatal("nested-marker");
    expect(isFileLogLevelEnabled("fatal")).toBe(false);
    expect(fs.existsSync(file)).toBe(false);
    expect(warnings).not.toHaveBeenCalled();
    expect(transport).not.toHaveBeenCalled();
  } finally {
    unregister();
    warnings.mockRestore();
  }
});

it("children preserve inherited thresholds and explicit overrides for every transport", () => {
  const file = path.join(directory, "child-overrides.log");
  const transport = vi.fn();
  const unregister = registerLogTransport(transport);
  try {
    setLoggerOverride({ level: "warn", file });
    const inherited = getChildLogger({ module: "inherited" });
    inherited.info("hidden-info");
    inherited.warn("inherited-warn");
    const nested = inherited.getSubLogger({ name: "nested" });
    nested.debug("hidden-debug");
    nested.error("nested-error");

    const verbose = getChildLogger({ module: "verbose" }, { level: "debug" });
    verbose.trace("hidden-trace");
    verbose.debug("explicit-debug");
    verbose.getSubLogger({ name: "nested" }).info("explicit-nested-info");

    const silent = getChildLogger({ module: "silent" }, { level: "silent" });
    silent.fatal("hidden-fatal");
    silent.getSubLogger({ name: "nested" }).fatal("hidden-nested-fatal");

    const output = fs.readFileSync(file, "utf8");
    const transported = JSON.stringify(transport.mock.calls);
    for (const marker of [
      "inherited-warn",
      "nested-error",
      "explicit-debug",
      "explicit-nested-info",
    ]) {
      expect(output).toContain(marker);
      expect(transported).toContain(marker);
    }
    expect(output).not.toContain("hidden-");
    expect(transported).not.toContain("hidden-");
    expect(transport).toHaveBeenCalledTimes(4);
  } finally {
    unregister();
  }
});
