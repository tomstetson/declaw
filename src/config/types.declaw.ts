/**
 * DeClaw observability config types.
 *
 * Added to OpenClawConfig as `declaw?: DeclawObservabilityConfig`.
 * Validated by declaw-doctor checks O1 (audit trail) and O2 (SIEM endpoint).
 */

export type DeclawAuditConfig = {
  /** Enable audit trail writing. Default: true. */
  enabled?: boolean;
  /** Override audit log path. Default: ~/.declaw/audit.jsonl. */
  path?: string;
};

export type DeclawSiemConfig = {
  /** Enable SIEM forwarding. Default: false. */
  enabled?: boolean;
  /** HTTP endpoint URL for event forwarding (e.g., Splunk HEC URL). */
  endpoint?: string;
  /** Additional HTTP headers (e.g., Authorization). Values support secret:// URIs. */
  headers?: Record<string, string>;
  /** Request timeout in ms. Default: 5000. */
  timeoutMs?: number;
};

export type DeclawMetricsConfig = {
  /** Enable in-memory metrics counters. Default: true. */
  enabled?: boolean;
};

export type DeclawObservabilityConfig = {
  audit?: DeclawAuditConfig;
  siem?: DeclawSiemConfig;
  metrics?: DeclawMetricsConfig;
};
