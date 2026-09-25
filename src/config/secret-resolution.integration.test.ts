/**
 * End-to-end integration test for the secret:// URI resolution chain.
 *
 * This test exercises the REAL pipeline with NO mocks:
 *   resolveConfigEnvVars → resolveSecret → execFileSync → Python declaw-secrets → EnvFileProvider
 *
 * Uses DECLAW_SECRETS_PROVIDER=env and a temporary HOME directory so the
 * EnvFileProvider reads from a controlled secrets.env file.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecretNotFoundError } from "../lib/secrets.js";
import { MissingEnvVarError, resolveConfigEnvVars } from "./env-substitution.js";

describe("secret:// URI resolution (integration)", () => {
  let tmpHome: string;
  let secretsDir: string;
  let envFixturePath: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "declaw-integ-"));
    secretsDir = path.join(tmpHome, ".declaw");
    envFixturePath = path.join(secretsDir, "secrets.env");
    fs.mkdirSync(secretsDir, { recursive: true });

    // Force the env-file provider and redirect HOME so the Python script
    // reads from our temp secrets.env instead of the real user's vault.
    vi.stubEnv("DECLAW_SECRETS_PROVIDER", "env");
    vi.stubEnv("HOME", tmpHome);
    vi.stubEnv("USERPROFILE", tmpHome);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  // -- Happy path -------------------------------------------------------

  it("resolves a single secret:// URI through the full chain", () => {
    fs.writeFileSync(envFixturePath, 'ANTHROPIC_API_KEY="test-key"\n');

    const config = {
      models: {
        providers: {
          anthropic: { apiKey: "secret://ANTHROPIC_API_KEY" },
        },
      },
    };

    const result = resolveConfigEnvVars(config);
    expect(result).toEqual({
      models: {
        providers: {
          anthropic: { apiKey: "test-key" },
        },
      },
    });
  });

  it("resolves multiple secret:// URIs in a single config", () => {
    fs.writeFileSync(envFixturePath, 'KEY_A="value-alpha"\nKEY_B="value-bravo"\n');

    const config = {
      providers: {
        a: { apiKey: "secret://KEY_A" },
        b: { apiKey: "secret://KEY_B" },
      },
    };

    const result = resolveConfigEnvVars(config);
    expect(result).toEqual({
      providers: {
        a: { apiKey: "value-alpha" },
        b: { apiKey: "value-bravo" },
      },
    });
  });

  it("mixes secret:// URIs with ${} env vars and plain strings", () => {
    fs.writeFileSync(envFixturePath, 'VAULT_SECRET="from-vault"\n');
    vi.stubEnv("ENV_TOKEN", "from-env");

    const config = {
      providers: {
        anthropic: { apiKey: "secret://VAULT_SECRET" },
        openai: { apiKey: "${ENV_TOKEN}" },
        local: { baseUrl: "http://localhost:8080" },
      },
      meta: { version: 42, enabled: true },
    };

    const result = resolveConfigEnvVars(config);
    expect(result).toEqual({
      providers: {
        anthropic: { apiKey: "from-vault" },
        openai: { apiKey: "from-env" },
        local: { baseUrl: "http://localhost:8080" },
      },
      meta: { version: 42, enabled: true },
    });
  });

  it("resolves secret:// URIs nested inside arrays", () => {
    fs.writeFileSync(envFixturePath, 'TOKEN_1="t1"\nTOKEN_2="t2"\n');

    const config = { tokens: ["secret://TOKEN_1", "secret://TOKEN_2"] };
    const result = resolveConfigEnvVars(config);
    expect(result).toEqual({ tokens: ["t1", "t2"] });
  });

  it("preserves Unicode secret values through Python on every platform", () => {
    fs.writeFileSync(envFixturePath, 'UNICODE_VALUE="café-雪-🔑"\n', "utf-8");
    expect(resolveConfigEnvVars({ key: "secret://UNICODE_VALUE" })).toEqual({ key: "café-雪-🔑" });
  });

  it("does not execute startup code from a configured Python user base", () => {
    const userBase = path.join(tmpHome, "python-user-base");
    vi.stubEnv("PYTHONUSERBASE", userBase);
    const interpreter = process.platform === "win32" ? "python" : "python3";
    const userSite = execFileSync(
      interpreter,
      ["-s", "-c", "import site; print(site.getusersitepackages())"],
      { encoding: "utf8" },
    ).trim();
    expect(path.relative(userBase, userSite).startsWith("..")).toBe(false);
    fs.mkdirSync(userSite, { recursive: true });
    const marker = path.join(tmpHome, "startup-code-ran");
    fs.writeFileSync(
      path.join(userSite, "synthetic-startup.pth"),
      `import pathlib; pathlib.Path(${JSON.stringify(marker)}).write_text("executed")\n`,
    );
    fs.writeFileSync(envFixturePath, 'VALID_KEY="synthetic-control"\n');
    expect(resolveConfigEnvVars({ key: "secret://VALID_KEY" })).toEqual({
      key: "synthetic-control",
    });
    expect(fs.existsSync(marker)).toBe(false);
  });

  // -- Error cases -------------------------------------------------------

  it("throws SecretNotFoundError for a missing secret", () => {
    fs.writeFileSync(envFixturePath, "");

    const config = { apiKey: "secret://NONEXISTENT_KEY" };
    expect(() => resolveConfigEnvVars(config)).toThrow(SecretNotFoundError);
  });

  it("throws descriptive error for invalid secret URI syntax", () => {
    const config = { key: "secret://invalid.name.with.dots" };
    expect(() => resolveConfigEnvVars(config)).toThrowError(/Invalid secret URI/);
  });

  it("throws MissingEnvVarError for missing ${} env var (not confused with secret://)", () => {
    const config = { key: "${TOTALLY_MISSING_VAR}" };
    expect(() => resolveConfigEnvVars(config)).toThrow(MissingEnvVarError);
  });
});
