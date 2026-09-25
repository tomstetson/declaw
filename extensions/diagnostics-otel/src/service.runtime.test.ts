import { expect, test, vi } from "vitest";

const state = vi.hoisted(() => ({
  transport: undefined as ((record: Record<string, unknown>) => void) | undefined,
  records: [] as { body?: unknown }[],
  forceFlush: vi.fn().mockResolvedValue(undefined),
  shutdown: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@opentelemetry/exporter-logs-otlp-proto", () => ({
  OTLPLogExporter: class {
    export(records: { body?: unknown }[], callback: (result: { code: number }) => void) {
      state.records.push(...records);
      callback({ code: 0 });
    }
    forceFlush = state.forceFlush;
    shutdown = state.shutdown;
  },
}));

vi.mock("openclaw/plugin-sdk", async () => {
  const actual = await vi.importActual<typeof import("openclaw/plugin-sdk")>("openclaw/plugin-sdk");
  return {
    ...actual,
    registerLogTransport: (transport: (record: Record<string, unknown>) => void) => {
      state.transport = transport;
      return () => {
        state.transport = undefined;
      };
    },
  };
});

import { createDiagnosticsOtelService } from "./service.js";

test("real log processor exports buffered records and closes its exporter on stop", async () => {
  const service = createDiagnosticsOtelService();
  const ctx = {
    config: {
      diagnostics: {
        enabled: true,
        otel: { enabled: true, traces: false, metrics: false, logs: true },
      },
    },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    stateDir: "/tmp/openclaw-diagnostics-otel-runtime-test",
  };
  await service.start(ctx);
  expect(state.transport).toBeTypeOf("function");
  state.transport?.({
    0: "offline maintenance control",
    _meta: { logLevelName: "INFO", date: new Date() },
  });
  await service.stop?.(ctx);
  expect(state.records.map((record) => record.body)).toEqual(["offline maintenance control"]);
  expect(state.shutdown).toHaveBeenCalledExactlyOnceWith();
  expect(state.forceFlush).toHaveBeenCalledExactlyOnceWith();
  expect(state.transport).toBeUndefined();
  expect(ctx.logger.error).not.toHaveBeenCalled();
});
