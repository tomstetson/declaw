/**
 * DeClaw Egress Policy — Network restriction enforcement for sandboxed containers.
 *
 * Controls outbound network access from Docker sandbox containers. Works with
 * OpenClaw's existing network mode configuration to enforce security intent.
 *
 * Modes:
 *   - "deny-all"      — Force network=none. No egress. (Recommended default)
 *   - "restricted"     — Allow network=bridge but require explicit DNS servers.
 *                        Warns if no DNS restrictions are set.
 *   - "unrestricted"   — Allow any network config. Logs security warning.
 *
 * Configured at `agents.defaults.sandbox.docker.egressPolicy` or per-agent
 * at `agents.list[].sandbox.docker.egressPolicy`.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DeclawEgressMode = "deny-all" | "restricted" | "unrestricted";

export type DeclawEgressPolicyConfig = {
  /** Egress filtering mode. */
  mode: DeclawEgressMode;
  /**
   * Allowed DNS servers when mode is "restricted".
   * Overrides any configured dns servers. If empty in restricted mode,
   * the system DNS is used (less secure but functional).
   */
  allowedDns?: string[];
  /**
   * Allowed extra host mappings when mode is "restricted".
   * Format: ["hostname:ip", ...]. Replaces configured extraHosts.
   */
  allowedHosts?: string[];
};

export type DeclawEgressValidation = {
  valid: boolean;
  warnings: string[];
  errors: string[];
  /** The effective network mode after policy enforcement. */
  effectiveNetwork: string;
};

// Subset of SandboxDockerConfig we need for validation/enforcement
export type DockerNetworkConfig = {
  network: string;
  dns?: string[];
  extraHosts?: string[];
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate a Docker sandbox config against the egress policy.
 * Returns warnings and errors without mutating the config.
 */
export function validateEgressPolicy(
  dockerConfig: DockerNetworkConfig,
  policy: DeclawEgressPolicyConfig | undefined,
): DeclawEgressValidation {
  if (!policy) {
    // No policy configured — pass through with a recommendation
    if (dockerConfig.network !== "none") {
      return {
        valid: true,
        warnings: [
          `sandbox network is "${dockerConfig.network}" with no egress policy. ` +
            'Consider setting egressPolicy.mode to "deny-all" for security.',
        ],
        errors: [],
        effectiveNetwork: dockerConfig.network,
      };
    }
    return {
      valid: true,
      warnings: [],
      errors: [],
      effectiveNetwork: dockerConfig.network,
    };
  }

  const warnings: string[] = [];
  const errors: string[] = [];

  if (policy.mode === "deny-all") {
    if (dockerConfig.network !== "none") {
      errors.push(
        `egress policy is "deny-all" but network is "${dockerConfig.network}". ` +
          'Network will be forced to "none".',
      );
    }
    return {
      valid: errors.length === 0,
      warnings,
      errors,
      effectiveNetwork: "none",
    };
  }

  if (policy.mode === "restricted") {
    if (dockerConfig.network === "none") {
      warnings.push(
        'egress policy is "restricted" but network is "none". ' +
          "No egress is possible. Set network to a bridge mode if egress is needed.",
      );
      return {
        valid: true,
        warnings,
        errors,
        effectiveNetwork: "none",
      };
    }

    // In restricted mode, DNS should be explicitly configured
    const effectiveDns = policy.allowedDns ?? dockerConfig.dns;
    if (!effectiveDns || effectiveDns.length === 0) {
      warnings.push(
        'egress policy is "restricted" but no DNS servers are configured. ' +
          "Containers will use system DNS, which may allow unrestricted domain resolution. " +
          "Set egressPolicy.allowedDns for tighter control.",
      );
    }

    const blocked = getBlockedNetworkForRestricted(dockerConfig.network);
    if (blocked) {
      errors.push(blocked);
    }

    return {
      valid: errors.length === 0,
      warnings,
      errors,
      effectiveNetwork: dockerConfig.network,
    };
  }

  if (policy.mode === "unrestricted") {
    warnings.push(
      'egress policy is "unrestricted". Sandbox containers have full outbound network access. ' +
        "This weakens sandbox isolation.",
    );
    return {
      valid: true,
      warnings,
      errors,
      effectiveNetwork: dockerConfig.network,
    };
  }

  // Unknown mode
  errors.push(`unknown egress policy mode: ${policy.mode as string}`);
  return {
    valid: false,
    warnings,
    errors,
    effectiveNetwork: dockerConfig.network,
  };
}

/**
 * Check if a network mode is too dangerous for "restricted" mode.
 */
function getBlockedNetworkForRestricted(network: string): string | null {
  const normalized = network.trim().toLowerCase();
  if (normalized === "host") {
    return 'network "host" is not compatible with restricted egress policy. Use "bridge" or a custom network.';
  }
  if (normalized.startsWith("container:")) {
    return `network "${network}" (container namespace join) is not compatible with restricted egress policy.`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/**
 * Apply the egress policy to a Docker config, returning the enforced values.
 * This is called during sandbox config resolution to override network settings.
 *
 * Returns a partial config object that should be spread over the resolved docker config.
 */
export function enforceEgressPolicy(
  dockerConfig: DockerNetworkConfig,
  policy: DeclawEgressPolicyConfig | undefined,
): Partial<DockerNetworkConfig> {
  if (!policy) {
    return {};
  }

  if (policy.mode === "deny-all") {
    // Force network=none, strip DNS config (irrelevant without network)
    return {
      network: "none",
      dns: undefined,
      extraHosts: undefined,
    };
  }

  if (policy.mode === "restricted") {
    const overrides: Partial<DockerNetworkConfig> = {};

    // Apply DNS restrictions if policy specifies them
    if (policy.allowedDns && policy.allowedDns.length > 0) {
      overrides.dns = policy.allowedDns;
    }

    // Apply host restrictions if policy specifies them
    if (policy.allowedHosts) {
      overrides.extraHosts = policy.allowedHosts;
    }

    return overrides;
  }

  // "unrestricted" — no overrides
  return {};
}
