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

import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
  // Defense in depth: validate secret name before constructing shell command.
  // The caller (parseSecretUri) also validates, but resolveSecret is a public
  // function — any future caller must not be able to inject shell metacharacters.
  if (!/^[A-Za-z0-9_-]+$/.test(secretName)) {
    throw new SecretNotFoundError(secretName, configPath);
  }

  try {
    // Try to call declaw-secrets from the bundled scripts directory
    const declawSecretsPath = path.resolve(
      __dirname,
      "../../scripts/declaw-secrets/declaw-secrets",
    );

    const result = execSync(`"${declawSecretsPath}" get "${secretName}"`, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 5000, // 5 second timeout
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
    if (error instanceof Error && "stderr" in error) {
      const stderr = (error as { stderr?: string }).stderr || "";
      if (stderr.includes("not found") || stderr.includes("does not exist")) {
        throw new SecretNotFoundError(secretName, configPath, error as Error);
      }
    }

    // Otherwise, declaw-secrets itself is not available
    throw new SecretsManagerNotAvailableError(error as Error);
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

  // Validate secret name (must be non-empty, alphanumeric + underscore)
  if (!/^[A-Za-z0-9_-]+$/.test(secretName)) {
    return null;
  }

  return secretName;
}
