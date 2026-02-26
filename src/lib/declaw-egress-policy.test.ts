import { describe, expect, it } from "vitest";
import {
  enforceEgressPolicy,
  validateEgressPolicy,
  type DeclawEgressPolicyConfig,
  type DockerNetworkConfig,
} from "./declaw-egress-policy.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDockerConfig(overrides?: Partial<DockerNetworkConfig>): DockerNetworkConfig {
  return {
    network: "none",
    dns: undefined,
    extraHosts: undefined,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// validateEgressPolicy — no policy
// ---------------------------------------------------------------------------

describe("validateEgressPolicy — no policy", () => {
  it("passes with network=none and no policy", () => {
    const result = validateEgressPolicy(makeDockerConfig(), undefined);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(0);
    expect(result.effectiveNetwork).toBe("none");
  });

  it("warns when network is not none and no policy", () => {
    const result = validateEgressPolicy(makeDockerConfig({ network: "bridge" }), undefined);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("no egress policy");
    expect(result.effectiveNetwork).toBe("bridge");
  });
});

// ---------------------------------------------------------------------------
// validateEgressPolicy — deny-all
// ---------------------------------------------------------------------------

describe("validateEgressPolicy — deny-all", () => {
  const policy: DeclawEgressPolicyConfig = { mode: "deny-all" };

  it("passes with network=none", () => {
    const result = validateEgressPolicy(makeDockerConfig(), policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.effectiveNetwork).toBe("none");
  });

  it("errors when network is not none", () => {
    const result = validateEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('forced to "none"');
    expect(result.effectiveNetwork).toBe("none");
  });

  it("errors when network is a custom bridge", () => {
    const result = validateEgressPolicy(makeDockerConfig({ network: "my-custom-net" }), policy);
    expect(result.valid).toBe(false);
    expect(result.effectiveNetwork).toBe("none");
  });
});

// ---------------------------------------------------------------------------
// validateEgressPolicy — restricted
// ---------------------------------------------------------------------------

describe("validateEgressPolicy — restricted", () => {
  it("passes with bridge and DNS configured", () => {
    const policy: DeclawEgressPolicyConfig = {
      mode: "restricted",
      allowedDns: ["1.1.1.1"],
    };
    const result = validateEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(0);
    expect(result.effectiveNetwork).toBe("bridge");
  });

  it("warns when network is none in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const result = validateEgressPolicy(makeDockerConfig(), policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("No egress is possible");
    expect(result.effectiveNetwork).toBe("none");
  });

  it("warns when no DNS servers configured in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const result = validateEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("no DNS servers are configured");
  });

  it("blocks host network in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const result = validateEgressPolicy(makeDockerConfig({ network: "host" }), policy);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("not compatible with restricted");
  });

  it("blocks container namespace in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const result = validateEgressPolicy(makeDockerConfig({ network: "container:other" }), policy);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("not compatible with restricted");
  });

  it("accepts custom bridge networks in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = {
      mode: "restricted",
      allowedDns: ["10.0.0.1"],
    };
    const result = validateEgressPolicy(makeDockerConfig({ network: "my-isolated-net" }), policy);
    expect(result.valid).toBe(true);
    expect(result.effectiveNetwork).toBe("my-isolated-net");
  });

  it("uses docker DNS when policy does not specify allowedDns", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const dockerConfig = makeDockerConfig({
      network: "bridge",
      dns: ["10.0.0.53"],
    });
    const result = validateEgressPolicy(dockerConfig, policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(0); // docker DNS set, no warning
  });
});

// ---------------------------------------------------------------------------
// validateEgressPolicy — unrestricted
// ---------------------------------------------------------------------------

describe("validateEgressPolicy — unrestricted", () => {
  const policy: DeclawEgressPolicyConfig = { mode: "unrestricted" };

  it("passes with any network config but warns", () => {
    const result = validateEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("full outbound network access");
    expect(result.effectiveNetwork).toBe("bridge");
  });

  it("passes with network=none and warns", () => {
    const result = validateEgressPolicy(makeDockerConfig(), policy);
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// validateEgressPolicy — unknown mode
// ---------------------------------------------------------------------------

describe("validateEgressPolicy — unknown mode", () => {
  it("errors on unknown mode", () => {
    const policy = { mode: "yolo" } as unknown as DeclawEgressPolicyConfig;
    const result = validateEgressPolicy(makeDockerConfig(), policy);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("unknown egress policy mode");
  });
});

// ---------------------------------------------------------------------------
// enforceEgressPolicy
// ---------------------------------------------------------------------------

describe("enforceEgressPolicy", () => {
  it("returns empty overrides with no policy", () => {
    const overrides = enforceEgressPolicy(makeDockerConfig(), undefined);
    expect(overrides).toEqual({});
  });

  it("forces network=none in deny-all mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "deny-all" };
    const overrides = enforceEgressPolicy(
      makeDockerConfig({ network: "bridge", dns: ["1.1.1.1"] }),
      policy,
    );
    expect(overrides.network).toBe("none");
    expect(overrides.dns).toBeUndefined();
    expect(overrides.extraHosts).toBeUndefined();
  });

  it("applies DNS overrides in restricted mode", () => {
    const policy: DeclawEgressPolicyConfig = {
      mode: "restricted",
      allowedDns: ["10.0.0.53"],
      allowedHosts: ["api.internal:10.0.0.5"],
    };
    const overrides = enforceEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(overrides.dns).toEqual(["10.0.0.53"]);
    expect(overrides.extraHosts).toEqual(["api.internal:10.0.0.5"]);
    expect(overrides.network).toBeUndefined(); // doesn't override network in restricted mode
  });

  it("returns empty overrides in unrestricted mode", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "unrestricted" };
    const overrides = enforceEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(overrides).toEqual({});
  });

  it("does not add DNS in restricted mode when none specified in policy", () => {
    const policy: DeclawEgressPolicyConfig = { mode: "restricted" };
    const overrides = enforceEgressPolicy(makeDockerConfig({ network: "bridge" }), policy);
    expect(overrides.dns).toBeUndefined();
  });
});
