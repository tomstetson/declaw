import { describe, expect, it, vi } from "vitest";
import {
  isSecretUri,
  parseSecretUri,
  resolveSecret,
  SecretNotFoundError,
  SecretsManagerNotAvailableError,
} from "./secrets.js";

// Mock child_process so we never shell out to a real Python script
vi.mock("node:child_process", () => ({
  execSync: vi.fn(),
}));

// Import the mocked execSync so we can control its behavior per-test
import { execSync } from "node:child_process";
const mockedExecSync = vi.mocked(execSync);

describe("isSecretUri", () => {
  it("returns true for a valid secret:// URI", () => {
    expect(isSecretUri("secret://FOO")).toBe(true);
  });

  it("returns true for secret:// with complex name", () => {
    expect(isSecretUri("secret://MY_API_KEY_123")).toBe(true);
  });

  it("returns false for uppercase scheme (case-sensitive)", () => {
    expect(isSecretUri("SECRET://FOO")).toBe(false);
  });

  it("returns false for http:// URIs", () => {
    expect(isSecretUri("http://example.com")).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(isSecretUri("")).toBe(false);
  });

  it("returns true for bare secret:// prefix with no name", () => {
    // isSecretUri only checks prefix — parseSecretUri validates the name
    expect(isSecretUri("secret://")).toBe(true);
  });
});

describe("parseSecretUri", () => {
  it('extracts "API_KEY" from "secret://API_KEY"', () => {
    expect(parseSecretUri("secret://API_KEY")).toBe("API_KEY");
  });

  it("extracts names with hyphens", () => {
    expect(parseSecretUri("secret://my-key")).toBe("my-key");
  });

  it("extracts names with mixed case and numbers", () => {
    expect(parseSecretUri("secret://Token_v2")).toBe("Token_v2");
  });

  it("returns null for non-secret URIs", () => {
    expect(parseSecretUri("http://example.com")).toBeNull();
    expect(parseSecretUri("env://FOO")).toBeNull();
    expect(parseSecretUri("plain-string")).toBeNull();
  });

  it("returns null when name contains spaces", () => {
    expect(parseSecretUri("secret://HAS SPACE")).toBeNull();
  });

  it("returns null when name contains dots", () => {
    expect(parseSecretUri("secret://has.dot")).toBeNull();
  });

  it("returns null when name contains slashes", () => {
    expect(parseSecretUri("secret://path/to/key")).toBeNull();
  });

  it("returns null for empty name after prefix", () => {
    expect(parseSecretUri("secret://")).toBeNull();
  });
});

describe("resolveSecret", () => {
  it("returns trimmed secret value on success", () => {
    mockedExecSync.mockReturnValueOnce("  my-secret-value  \n");

    const result = resolveSecret("API_KEY", "models.providers.anthropic.apiKey");

    expect(result).toBe("my-secret-value");
    expect(mockedExecSync).toHaveBeenCalledWith(
      expect.stringContaining('"API_KEY"'),
      expect.objectContaining({ encoding: "utf-8", timeout: 5000 }),
    );
  });

  it("throws SecretNotFoundError when result is empty", () => {
    mockedExecSync.mockReturnValueOnce("   \n");

    expect(() => resolveSecret("EMPTY_SECRET", "config.key")).toThrow(SecretNotFoundError);
  });

  it("throws SecretNotFoundError when stderr contains 'not found'", () => {
    const error = new Error("Process exited with code 1") as Error & { stderr: string };
    error.stderr = "Error: secret 'MISSING' not found in vault";
    mockedExecSync.mockImplementationOnce(() => {
      throw error;
    });

    expect(() => resolveSecret("MISSING", "config.key")).toThrow(SecretNotFoundError);
  });

  it("throws SecretNotFoundError when stderr contains 'does not exist'", () => {
    const error = new Error("Process exited with code 1") as Error & { stderr: string };
    error.stderr = "secret does not exist";
    mockedExecSync.mockImplementationOnce(() => {
      throw error;
    });

    expect(() => resolveSecret("GONE", "config.key")).toThrow(SecretNotFoundError);
  });

  it("throws SecretsManagerNotAvailableError when script is missing", () => {
    const error = new Error("ENOENT: no such file or directory");
    mockedExecSync.mockImplementationOnce(() => {
      throw error;
    });

    expect(() => resolveSecret("ANY", "config.key")).toThrow(SecretsManagerNotAvailableError);
  });

  it("throws SecretsManagerNotAvailableError for generic exec failures", () => {
    const error = new Error("Command failed: timeout");
    mockedExecSync.mockImplementationOnce(() => {
      throw error;
    });

    expect(() => resolveSecret("ANY", "config.key")).toThrow(SecretsManagerNotAvailableError);
  });

  it("rejects secret names containing shell metacharacters", () => {
    // Defense in depth: resolveSecret validates internally even though
    // parseSecretUri also validates. This prevents injection if resolveSecret
    // is called directly with an unsanitized name.
    mockedExecSync.mockClear();
    expect(() => resolveSecret('foo"; rm -rf /', "config.key")).toThrow(SecretNotFoundError);
    expect(mockedExecSync).not.toHaveBeenCalled();
  });

  it("rejects secret names with spaces", () => {
    mockedExecSync.mockClear();
    expect(() => resolveSecret("HAS SPACE", "config.key")).toThrow(SecretNotFoundError);
    expect(mockedExecSync).not.toHaveBeenCalled();
  });

  it("rejects secret names with backticks", () => {
    mockedExecSync.mockClear();
    expect(() => resolveSecret("`whoami`", "config.key")).toThrow(SecretNotFoundError);
    expect(mockedExecSync).not.toHaveBeenCalled();
  });

  it("rejects secret names with dollar signs", () => {
    mockedExecSync.mockClear();
    expect(() => resolveSecret("$(id)", "config.key")).toThrow(SecretNotFoundError);
    expect(mockedExecSync).not.toHaveBeenCalled();
  });

  it("accepts valid secret names with underscores and hyphens", () => {
    mockedExecSync.mockReturnValueOnce("value\n");
    expect(() => resolveSecret("MY_API-KEY_v2", "config.key")).not.toThrow();
  });
});

describe("error classes", () => {
  it("SecretNotFoundError includes secret name and config path", () => {
    const err = new SecretNotFoundError("MY_SECRET", "models.apiKey");

    expect(err.name).toBe("SecretNotFoundError");
    expect(err.secretName).toBe("MY_SECRET");
    expect(err.configPath).toBe("models.apiKey");
    expect(err.message).toContain("MY_SECRET");
    expect(err.message).toContain("models.apiKey");
    expect(err.message).toContain("declaw-secrets set MY_SECRET");
  });

  it("SecretNotFoundError preserves original cause", () => {
    const cause = new Error("underlying issue");
    const err = new SecretNotFoundError("KEY", "path", cause);

    expect(err.cause).toBe(cause);
  });

  it("SecretsManagerNotAvailableError includes install instructions", () => {
    const err = new SecretsManagerNotAvailableError();

    expect(err.name).toBe("SecretsManagerNotAvailableError");
    expect(err.message).toContain("not available");
    expect(err.message).toContain("npm install -g declaw");
  });

  it("SecretsManagerNotAvailableError preserves original cause", () => {
    const cause = new Error("ENOENT");
    const err = new SecretsManagerNotAvailableError(cause);

    expect(err.cause).toBe(cause);
  });
});
