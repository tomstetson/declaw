/**
 * DeClaw Secrets Manager Integration
 *
 * Resolves `secret://SECRET_NAME` URIs in config values by calling declaw-secrets.
 *
 * @example
 * ```json5
 * {
 *   env: {
 *     ANTHROPIC_API_KEY: "secret://ANTHROPIC_API_KEY"
 *   }
 * }
 * ```
 */

import { execFileSync } from "node:child_process";
import path from "node:path";
import { resolveOpenClawPackageRootSync } from "../infra/openclaw-root.js";

const SECRET_NAME = /^[A-Za-z0-9_][A-Za-z0-9_-]*$/;
const PROVIDERS = new Set(["keychain", "vault", "bitwarden", "1password", "env"]);

export class SecretNotFoundError extends Error {
  constructor(
    public readonly secretName: string,
    public readonly configPath: string,
    public readonly cause?: Error,
  ) {
    super(
      `Secret "${secretName}" not found (referenced at: ${configPath})\n` +
        `Run: declaw-secrets set ${secretName}`,
    );
    this.name = "SecretNotFoundError";
  }
}

export class SecretsManagerNotAvailableError extends Error {
  constructor(public readonly cause?: Error) {
    super(
      "DeClaw secrets manager not available\n" +
        "Install: npm install -g declaw\n" +
        "Or use environment variables instead of secret:// URIs",
    );
    this.name = "SecretsManagerNotAvailableError";
  }
}

/**
 * Resolve a single secret from declaw-secrets.
 *
 * @param secretName - The secret name (from secret://SECRET_NAME)
 * @param configPath - Config path for error messages
 * @returns The secret value
 * @throws {SecretNotFoundError} If secret doesn't exist
 * @throws {SecretsManagerNotAvailableError} If declaw-secrets is not available
 */
export function resolveSecret(secretName: string, configPath: string): string {
  // Reject option-like keys consistently, including for downstream provider CLIs.
  if (!SECRET_NAME.test(secretName)) {
    throw new SecretNotFoundError(secretName, configPath);
  }

  const provider = process.env.DECLAW_SECRETS_PROVIDER;
  if (provider && !PROVIDERS.has(provider)) {
    throw new SecretsManagerNotAvailableError();
  }

  try {
    // Resolve from this module, never from an operator-controlled working directory.
    const packageRoot = resolveOpenClawPackageRootSync({ moduleUrl: import.meta.url });
    if (!packageRoot) {
      throw new SecretsManagerNotAvailableError();
    }
    const declawSecretsPath = path.join(packageRoot, "scripts", "declaw-secrets", "declaw-secrets");
    // Isolated Python ignores PYTHON* startup hooks and the user site directory.
    const args = ["-I", "-X", "utf8", declawSecretsPath];
    if (provider) {
      args.push("--provider", provider);
    }
    args.push("get", "--", secretName);
    const result = execFileSync(process.platform === "win32" ? "python" : "python3", args, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 5000,
    });

    const secretValue = result.trim();

    if (!secretValue) {
      throw new SecretNotFoundError(secretName, configPath);
    }

    return secretValue;
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      throw error;
    }

    // If exec failed, check if it's because the secret doesn't exist
    // Native child-process errors can originate in another VM realm.
    if (typeof error === "object" && error !== null && "stderr" in error) {
      const rawStderr = (error as { stderr?: unknown }).stderr;
      const stderr =
        typeof rawStderr === "string"
          ? rawStderr
          : Buffer.isBuffer(rawStderr)
            ? rawStderr.toString("utf8")
            : "";
      if (stderr.includes("not found") || stderr.includes("does not exist")) {
        throw new SecretNotFoundError(secretName, configPath);
      }
    }

    // Child errors can retain secret stdout/stderr. Never attach them to public errors.
    throw new SecretsManagerNotAvailableError();
  }
}

/**
 * Check if a string value is a secret:// URI.
 */
export function isSecretUri(value: string): boolean {
  return value.startsWith("secret://");
}

/**
 * Extract the secret name from a secret:// URI.
 *
 * @example
 * parseSecretUri("secret://API_KEY") // => "API_KEY"
 */
export function parseSecretUri(uri: string): string | null {
  if (!isSecretUri(uri)) {
    return null;
  }

  const secretName = uri.slice("secret://".length);

  // A key cannot begin with a hyphen: providers may interpret it as an option.
  if (!SECRET_NAME.test(secretName)) {
    return null;
  }

  return secretName;
}
